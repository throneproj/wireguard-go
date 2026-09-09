/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type QueueOutboundElement struct {
	buffer []byte // sing-allocated buffer holding the packet data
	// packet is always a slice of "buffer". The starting offset in buffer
	// is either:
	//  a) MessageEncapsulatingTransportSize+padding+MessageTransportHeaderSize (plaintext)
	//  b) 0 (post-encryption)
	packet  []byte
	nonce   uint64   // nonce for encryption
	keypair *Keypair // keypair for encryption
	peer    *Peer    // related peer
	// padding is the AmneziaWG S4 crypto padding size this element was laid
	// out with. It is captured per element because S4 can change under an IPC
	// set while elements are already in flight.
	padding uint32
	// isKeepalive marks an element queued by SendKeepalive. AmneziaWG content
	// padding makes an encrypted keepalive indistinguishable from a data
	// packet by size alone, so the intent has to be carried explicitly.
	isKeepalive bool
}

type QueueOutboundElementsContainer struct {
	// filling is a one-shot barrier signaling encryption→send handoff.
	// SendStagedPackets calls Add(1) before sending the container down
	// the encryption and outbound queues; RoutineEncryption calls Done
	// after encrypting; RoutineSequentialSender calls Wait before
	// reading the encrypted packets.
	filling sync.WaitGroup
	elems   []*QueueOutboundElement
}

func (device *Device) NewOutboundElement() *QueueOutboundElement {
	elem := device.GetOutboundElement()
	elem.buffer = device.GetOutboundBuffer(MaxMessageSize)
	elem.nonce = 0
	elem.padding = device.paddings.transport.Load()
	elem.isKeepalive = false
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
	// Reset here rather than at each allocation site: elements are recycled
	// through GetOutboundElement, which does not clear them.
	elem.isKeepalive = false
}

/* Queues a keepalive if no packets are queued for peer
 */
func (peer *Peer) SendKeepalive() {
	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		elem := peer.device.NewOutboundElement()
		elem.isKeepalive = true
		elemsContainer := peer.device.GetOutboundElementsContainer()
		elemsContainer.elems = append(elemsContainer.elems, elem)
		select {
		case peer.queue.staged <- elemsContainer:
			peer.queuedOutboundPackets.Add(1)
			peer.device.log.Verbosef("%v - Sending keepalive packet", peer)
		default:
			peer.device.PutOutboundBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}
	peer.SendStagedPackets()
}

// SendPriorityMessage invokes the [PeerPriorityMessageFunc] callback if one is
// set, and queues the returned message for encryption and transmission if the
// current keypair is valid.
func (peer *Peer) SendPriorityMessage() {
	f := peer.device.priorityMsgFn.Load()
	if f == nil {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || time.Since(keypair.created) >= RejectAfterTime {
		// SendStagedPackets initializes a handshake when the keypair is invalid,
		// but we explicitly avoid that here. A priority message is only intended
		// to flow around symmetric session establishment, but it should never
		// trigger a new session. Reaching this branch due to nonce exhaustion
		// or keypair expiration is highly unlikely considering where
		// SendPriorityMessage is called (at current keypair establishment).
		return
	}

	// get plaintext message to send
	msg := (*f)(peer.handshake.remoteStatic)
	if len(msg) == 0 {
		return
	}
	if len(msg) > MaxPriorityMessageContentSize {
		peer.device.log.Verbosef("%v - Failed to queue priority message due to size", peer)
		return
	}

	// get pooled elements
	elem := peer.device.NewOutboundElement()
	elemsContainer := peer.device.GetOutboundElementsContainer()
	elemsContainer.elems = append(elemsContainer.elems, elem)
	packetQueued := false
	defer func() {
		if !packetQueued {
			peer.device.PutOutboundBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}()

	// initialize outbound element. The AmneziaWG S4 crypto padding sits ahead of
	// the transport header, so the content starts past it; RoutineEncryption
	// reads the same layout back out of elem.padding.
	offset := MessageEncapsulatingTransportSize + int(elem.padding) + MessageTransportHeaderSize
	if offset+len(msg)+poly1305.TagSize > len(elem.buffer) {
		// Only reachable with a large S4, which eats into the space the
		// MaxPriorityMessageContentSize check above assumes is free.
		peer.device.log.Verbosef("%v - Failed to queue priority message due to size", peer)
		return
	}
	n := copy(elem.buffer[offset:], msg)
	elem.packet = elem.buffer[offset : offset+n]
	elem.peer = peer
	elem.nonce = keypair.sendNonce.Add(1) - 1
	if elem.nonce >= RejectAfterMessages {
		keypair.sendNonce.Store(RejectAfterMessages)
		return
	}
	elem.keypair = keypair

	// add to parallel and sequential queue
	if peer.isRunning.Load() {
		elemsContainer.filling.Add(1)
		peer.queuedOutboundPackets.Add(1)
		peer.queue.outbound.c <- elemsContainer
		peer.device.queue.encryption.c <- elemsContainer
		packetQueued = true
	}
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
		peer.timers.maxHandshakeAttempts.Store(peer.device.maxHandshakeAttempts())
	}

	timeout := peer.device.rekeyMinTimeout()

	peer.handshake.mutex.RLock()
	if time.Since(peer.handshake.lastSentHandshake) < timeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if time.Since(peer.handshake.lastSentHandshake) < timeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake initiation", peer)

	candidates := peer.resolveEndpoints()

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create initiation message: %v", peer, err)
		return err
	}

	var sendBuffer [][]byte

	// AmneziaWG I1-I5 signature packets, emitted before the handshake.
	for _, ipacket := range peer.device.ipackets {
		if ipacket != nil {
			ibuf := make([]byte, MessageEncapsulatingTransportSize+ipacket.ObfuscatedLen(0))
			ipacket.Obfuscate(ibuf[MessageEncapsulatingTransportSize:], nil)
			sendBuffer = append(sendBuffer, ibuf)
		}
	}

	// AmneziaWG Jc junk packets, each a random size in [Jmin, Jmax).
	sendBuffer = append(sendBuffer, peer.device.JunkPackets()...)

	// AmneziaWG S1: prefix the initiation with random padding bytes, whose
	// leading bytes double as the header protection nonce.
	padding := int(peer.device.paddings.init.Load())
	// AmneziaWG random trailers: suffix the initiation with random bytes so it
	// is no longer identifiable by its fixed size.
	trailerLen := max(peer.randomTrailer(padding+MessageInitiationSize), 0)
	offset := MessageEncapsulatingTransportSize + padding

	buf := make([]byte, offset+MessageInitiationSize+trailerLen)
	crypt := buf[MessageEncapsulatingTransportSize:offset]
	rand.Read(crypt)

	packet := buf[offset : offset+MessageInitiationSize]
	_ = msg.marshal(packet)
	peer.cookieGenerator.AddMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	cip, err := peer.device.HeaderProtectionCipher(crypt)
	if err != nil {
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	rand.Read(buf[offset+MessageInitiationSize:])

	sendBuffer = append(sendBuffer, buf)

	if len(candidates) > 0 {
		err = peer.sendHandshakeBuffers(sendBuffer, candidates)
	} else {
		err = peer.SendBuffers(sendBuffer)
	}
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake initiation: %v", peer, err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake response", peer)

	response, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create response message: %v", peer, err)
		return err
	}

	// AmneziaWG S2: prefix the response with random padding bytes, whose
	// leading bytes double as the header protection nonce.
	padding := int(peer.device.paddings.response.Load())
	// AmneziaWG random trailers: suffix the response with random bytes so it
	// is no longer identifiable by its fixed size.
	trailerLen := max(peer.randomTrailer(padding+MessageResponseSize), 0)
	offset := MessageEncapsulatingTransportSize + padding

	buf := make([]byte, offset+MessageResponseSize+trailerLen)
	crypt := buf[MessageEncapsulatingTransportSize:offset]
	rand.Read(crypt)

	packet := buf[offset : offset+MessageResponseSize]
	_ = response.marshal(packet)
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	cip, err := peer.device.HeaderProtectionCipher(crypt)
	if err != nil {
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	rand.Read(buf[offset+MessageResponseSize:])

	// TODO: allocation could be avoided
	err = peer.SendBuffers([][]byte{buf})
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake response: %v", peer, err)
	}
	return err
}

func (device *Device) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	device.log.Verbosef("Sending cookie response for denied handshake message for %v", initiatingElem.endpoint.DstToString())

	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	reply, err := device.cookieChecker.CreateReply(initiatingElem.packet, sender, initiatingElem.endpoint.DstToBytes())
	if err != nil {
		device.log.Errorf("Failed to create cookie reply: %v", err)
		return err
	}
	// AmneziaWG H3: randomize the cookie-reply message type within its range.
	reply.Type = device.headers.cookie.Load().PickOne()

	// AmneziaWG S3: prefix the cookie reply with random padding bytes, whose
	// leading bytes double as the header protection nonce.
	padding := int(device.paddings.cookie.Load())
	// AmneziaWG random trailers: suffix the cookie reply with random bytes so
	// it is no longer identifiable by its fixed size.
	trailerLen := max(device.randomTrailer(padding+MessageCookieReplySize), 0)
	offset := MessageEncapsulatingTransportSize + padding

	buf := make([]byte, offset+MessageCookieReplySize+trailerLen)
	crypt := buf[MessageEncapsulatingTransportSize:offset]
	rand.Read(crypt)

	packet := buf[offset : offset+MessageCookieReplySize]
	_ = reply.marshal(packet)

	cip, err := device.HeaderProtectionCipher(crypt)
	if err != nil {
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	rand.Read(buf[offset+MessageCookieReplySize:])

	// TODO: allocation could be avoided
	device.net.bind.Send([][]byte{buf}, initiatingElem.endpoint, MessageEncapsulatingTransportSize)

	return nil
}

func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := keypair.sendNonce.Load()
	if nonce > RekeyAfterMessages || (keypair.isInitiator && time.Since(keypair.created) > peer.device.keyRefreshTimeoutSending()) {
		peer.SendHandshakeInitiation(false)
	}
}

func (device *Device) RoutineReadFromTUN() {
	defer func() {
		device.log.Verbosef("Routine: TUN reader - stopped")
		device.state.stopping.Done()
		device.queue.encryption.wg.Done()
	}()

	device.log.Verbosef("Routine: TUN reader - started")

	var (
		batchSize   = device.BatchSize()
		readErr     error
		elems       = make([]*QueueOutboundElement, batchSize)
		bufs        = make([][]byte, batchSize)
		elemsByPeer = make(map[*Peer]*QueueOutboundElementsContainer, batchSize)
		count       = 0
		sizes       = make([]int, batchSize)
	)

	for i := range elems {
		elems[i] = device.NewOutboundElement()
		bufs[i] = elems[i].buffer[:]
	}

	defer func() {
		for _, elem := range elems {
			if elem != nil {
				device.PutOutboundBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
		}
	}()

	for {
		padding := device.paddings.transport.Load()
		offset := MessageEncapsulatingTransportSize + int(padding) + MessageTransportHeaderSize

		// read packets
		count, readErr = device.tun.device.Read(bufs, sizes, offset)
		for i := 0; i < count; i++ {
			if sizes[i] < 1 {
				continue
			}

			elem := elems[i]
			elem.packet = bufs[i][offset : offset+sizes[i]]
			elem.padding = padding

			// lookup peer
			var peer *Peer
			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				src := netip.AddrFrom4([4]byte(elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]))
				dst := netip.AddrFrom4([4]byte(elem.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]))
				peer = device.allowedips.LookupFromPacket(src, dst, elem.packet)

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				src := netip.AddrFrom16([16]byte(elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]))
				dst := netip.AddrFrom16([16]byte(elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]))
				peer = device.allowedips.LookupFromPacket(src, dst, elem.packet)

			default:
				device.log.Verbosef("Received packet with unknown IP version")
			}

			if peer == nil {
				continue
			}
			elemsForPeer, ok := elemsByPeer[peer]
			if !ok {
				elemsForPeer = device.GetOutboundElementsContainer()
				elemsByPeer[peer] = elemsForPeer
			}
			elemsForPeer.elems = append(elemsForPeer.elems, elem)
			elems[i] = device.NewOutboundElement()
			bufs[i] = elems[i].buffer[:]
		}

		for peer, elemsForPeer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.StagePackets(elemsForPeer)
				peer.SendStagedPackets()
			} else {
				for _, elem := range elemsForPeer.elems {
					device.PutOutboundBuffer(elem.buffer)
					device.PutOutboundElement(elem)
				}
				device.PutOutboundElementsContainer(elemsForPeer)
			}
			delete(elemsByPeer, peer)
		}

		if readErr != nil {
			if errors.Is(readErr, tun.ErrTooManySegments) {
				// TODO: record stat for this
				// This will happen if MSS is surprisingly small (< 576)
				// coincident with reasonably high throughput.
				device.log.Verbosef("Dropped some packets from multi-segment read: %v", readErr)
				continue
			}
			if !device.isClosed() {
				if !errors.Is(readErr, os.ErrClosed) {
					device.log.Errorf("Failed to read packet from TUN device: %v", readErr)
				}
				go device.Close()
			}
			return
		}
	}
}

// maxQueuedInputPackets bounds the staged+outbound backlog of a peer fed via
// InputPacket/InputPackets. Injected packets beyond it are dropped before they
// are copied into pooled message buffers, like a full qdisc: injection has no
// flow control, and the queues are bounded in containers (up to a full batch
// each), so without this cap a flood is buffered instead of dropped.
const maxQueuedInputPackets = 2048

func (device *Device) inputPacketPeer(destination []byte, packetSlices [][]byte) *Peer {
	var src, dst netip.Addr
	switch len(destination) {
	case net.IPv4len:
		dst = netip.AddrFrom4([4]byte(destination))
		var srcBytes [net.IPv4len]byte
		if !gatherPacketBytes(packetSlices, IPv4offsetSrc, srcBytes[:]) {
			return nil
		}
		src = netip.AddrFrom4(srcBytes)
	case net.IPv6len:
		dst = netip.AddrFrom16([16]byte(destination))
		var srcBytes [net.IPv6len]byte
		if !gatherPacketBytes(packetSlices, IPv6offsetSrc, srcBytes[:]) {
			return nil
		}
		src = netip.AddrFrom16(srcBytes)
	default:
		return nil
	}
	var ipPkt []byte
	if len(packetSlices) == 1 {
		ipPkt = packetSlices[0]
	}
	return device.allowedips.LookupFromPacket(src, dst, ipPkt)
}

func gatherPacketBytes(packetSlices [][]byte, offset int, destination []byte) bool {
	for _, packetSlice := range packetSlices {
		if offset >= len(packetSlice) {
			offset -= len(packetSlice)
			continue
		}
		n := copy(destination, packetSlice[offset:])
		destination = destination[n:]
		offset = 0
		if len(destination) == 0 {
			return true
		}
	}
	return false
}

func (device *Device) InputPacket(destination []byte, packetSlices [][]byte) {
	peer := device.inputPacketPeer(destination, packetSlices)
	if peer == nil {
		return
	}
	if peer.queuedOutboundPackets.Load() >= maxQueuedInputPackets {
		return
	}
	var totalLength int
	for _, packetSlice := range packetSlices {
		totalLength += len(packetSlice)
	}
	// The AmneziaWG S4 crypto padding sits ahead of the transport header, so it
	// has to be part of the sized allocation as well as the packet offset.
	padding := device.paddings.transport.Load()
	allocLength := MessageEncapsulatingTransportSize + int(padding) + MessageTransportHeaderSize + totalLength + PaddingMultiple + chacha20poly1305.Overhead
	if allocLength > MaxMessageSize {
		return
	}
	elem := device.GetOutboundElement()
	elem.buffer = device.GetOutboundBuffer(allocLength)
	elem.nonce = 0
	elem.padding = padding
	packet := elem.buffer[MessageEncapsulatingTransportSize+int(padding)+MessageTransportHeaderSize:]
	var n int
	for _, packetSlice := range packetSlices {
		n += copy(packet[n:], packetSlice)
	}
	elem.packet = packet[:n]
	elemsForPeer := device.GetOutboundElementsContainer()
	if peer.isRunning.Load() {
		elemsForPeer.elems = append(elemsForPeer.elems, elem)
		peer.StagePackets(elemsForPeer)
		peer.SendStagedPackets()
	} else {
		device.PutOutboundBuffer(elem.buffer)
		device.PutOutboundElement(elem)
		device.PutOutboundElementsContainer(elemsForPeer)
	}
}

type InputPacketRef struct {
	Destination  []byte
	PacketSlices [][]byte
}

func (device *Device) InputPackets(packets []*InputPacketRef) []*InputPacketRef {
	var unmatched []*InputPacketRef
	elemsByPeer := make(map[*Peer][]*QueueOutboundElementsContainer, len(packets))
	for _, packetRef := range packets {
		peer := device.inputPacketPeer(packetRef.Destination, packetRef.PacketSlices)
		if peer == nil {
			unmatched = append(unmatched, packetRef)
			continue
		}
		if peer.queuedOutboundPackets.Load() >= maxQueuedInputPackets {
			continue
		}
		var totalLength int
		for _, packetSlice := range packetRef.PacketSlices {
			totalLength += len(packetSlice)
		}
		// As in InputPacket: reserve and record the AmneziaWG S4 padding.
		// GetOutboundElement recycles elements without clearing padding, so it
		// must be set explicitly rather than inherited from a prior use.
		padding := device.paddings.transport.Load()
		allocLength := MessageEncapsulatingTransportSize + int(padding) + MessageTransportHeaderSize + totalLength + PaddingMultiple + chacha20poly1305.Overhead
		if allocLength > MaxMessageSize {
			continue
		}
		elem := device.GetOutboundElement()
		elem.buffer = device.GetOutboundBuffer(allocLength)
		elem.nonce = 0
		elem.padding = padding
		packet := elem.buffer[MessageEncapsulatingTransportSize+int(padding)+MessageTransportHeaderSize:]
		var n int
		for _, packetSlice := range packetRef.PacketSlices {
			n += copy(packet[n:], packetSlice)
		}
		elem.packet = packet[:n]
		containers := elemsByPeer[peer]
		if len(containers) == 0 || len(containers[len(containers)-1].elems) >= conn.IdealBatchSize {
			containers = append(containers, device.GetOutboundElementsContainer())
			elemsByPeer[peer] = containers
		}
		elemsForPeer := containers[len(containers)-1]
		elemsForPeer.elems = append(elemsForPeer.elems, elem)
	}
	for peer, containers := range elemsByPeer {
		if peer.isRunning.Load() {
			for _, elemsForPeer := range containers {
				peer.StagePackets(elemsForPeer)
			}
			peer.SendStagedPackets()
		} else {
			for _, elemsForPeer := range containers {
				for _, elem := range elemsForPeer.elems {
					device.PutOutboundBuffer(elem.buffer)
					device.PutOutboundElement(elem)
				}
				device.PutOutboundElementsContainer(elemsForPeer)
			}
		}
	}
	return unmatched
}

func (peer *Peer) StagePackets(elems *QueueOutboundElementsContainer) {
	peer.queuedOutboundPackets.Add(int32(len(elems.elems)))
	for {
		select {
		case peer.queue.staged <- elems:
			return
		default:
		}
		select {
		case tooOld := <-peer.queue.staged:
			peer.queuedOutboundPackets.Add(-int32(len(tooOld.elems)))
			for _, elem := range tooOld.elems {
				peer.device.PutOutboundBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(tooOld)
		default:
		}
	}
}

func (peer *Peer) SendStagedPackets() {
top:
	if len(peer.queue.staged) == 0 || !peer.device.isUp() {
		return
	}

	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || time.Since(keypair.created) >= peer.device.keychainExpireTime() {
		peer.SendHandshakeInitiation(false)
		return
	}

	for {
		var elemsContainerOOO *QueueOutboundElementsContainer
		select {
		case elemsContainer := <-peer.queue.staged:
			i := 0
			for _, elem := range elemsContainer.elems {
				elem.peer = peer
				elem.nonce = keypair.sendNonce.Add(1) - 1
				if elem.nonce >= RejectAfterMessages {
					keypair.sendNonce.Store(RejectAfterMessages)
					if elemsContainerOOO == nil {
						elemsContainerOOO = peer.device.GetOutboundElementsContainer()
					}
					elemsContainerOOO.elems = append(elemsContainerOOO.elems, elem)
					continue
				} else {
					elemsContainer.elems[i] = elem
					i++
				}

				elem.keypair = keypair
			}
			elemsContainer.elems = elemsContainer.elems[:i]

			if elemsContainerOOO != nil {
				// Already counted at their original staging; StagePackets will count them again.
				peer.queuedOutboundPackets.Add(-int32(len(elemsContainerOOO.elems)))
				peer.StagePackets(elemsContainerOOO) // XXX: Out of order, but we can't front-load go chans
			}

			if len(elemsContainer.elems) == 0 {
				peer.device.PutOutboundElementsContainer(elemsContainer)
				goto top
			}

			// add to parallel and sequential queue
			if peer.isRunning.Load() {
				elemsContainer.filling.Add(1)
				peer.queue.outbound.c <- elemsContainer
				peer.device.queue.encryption.c <- elemsContainer
			} else {
				peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
				for _, elem := range elemsContainer.elems {
					peer.device.PutOutboundBuffer(elem.buffer)
					peer.device.PutOutboundElement(elem)
				}
				peer.device.PutOutboundElementsContainer(elemsContainer)
			}

			if elemsContainerOOO != nil {
				goto top
			}
		default:
			return
		}
	}
}

func (peer *Peer) FlushStagedPackets() {
	for {
		select {
		case elemsContainer := <-peer.queue.staged:
			peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
			for _, elem := range elemsContainer.elems {
				peer.device.PutOutboundBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}

func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

// randomPaddingAddition returns the AmneziaWG content padding to append to a
// transport message whose on-the-wire size is packetSize, or -1 when no
// ContentPaddingAddition range is configured and the WireGuard multiple-of-16
// padding should be used instead.
//
// Like randomTrailer, the result is capped so the padded message stays inside
// the largest size seen on this session.
func (peer *Peer) randomPaddingAddition(packetSize int) int {
	addition := peer.device.contentPaddingAddition.Load()

	if addition.IsZero() {
		return -1
	}

	udpWindow := int(peer.udpWindow.Load())
	if udpWindow < packetSize {
		return 0
	}

	add := int(addition.PickOne())
	if space := udpWindow - packetSize; add > space {
		add = space
	}
	return add
}

// randomTrailer returns the number of random bytes to append to a message of
// packetSize bytes, or -1 when the AmneziaWG random trailers feature is off.
//
// The device-level variant is used for messages not associated with a peer;
// it sizes against the default window since there is no observed session.
func (device *Device) randomTrailer(packetSize int) int {
	if !device.randomTrailers.Load() {
		return -1
	}
	if DefaultUdpWindow < packetSize {
		return 0
	}
	return int(fastrandn(uint32(DefaultUdpWindow - packetSize)))
}

// randomTrailer returns the number of random bytes to append to a message of
// packetSize bytes, or -1 when the AmneziaWG random trailers feature is off.
//
// The trailer is sized against the largest packet seen on this session, so
// padded messages stay inside a size range the path already carries.
func (peer *Peer) randomTrailer(packetSize int) int {
	if !peer.device.randomTrailers.Load() {
		return -1
	}
	udpWindow := int(peer.udpWindow.Load())
	if udpWindow < packetSize {
		return 0
	}
	return int(fastrandn(uint32(udpWindow - packetSize)))
}

// observeUdpWindow grows the peer's observed maximum packet size, which bounds
// the random trailers appended to subsequent messages.
func (peer *Peer) observeUdpWindow(size uint32) {
	for {
		current := peer.udpWindow.Load()
		if current >= size {
			return
		}
		if peer.udpWindow.CompareAndSwap(current, size) {
			return
		}
	}
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (device *Device) RoutineEncryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: encryption worker %d - stopped", id)
	device.log.Verbosef("Routine: encryption worker %d - started", id)

	for elemsContainer := range device.queue.encryption.c {
		for _, elem := range elemsContainer.elems {
			elem.peer.observeUdpWindow(elem.padding + MinMessageSize + uint32(len(elem.packet)))

			// AmneziaWG S4: fill the crypto padding that precedes the transport
			// header; its leading bytes double as the header protection nonce.
			crypt := elem.buffer[MessageEncapsulatingTransportSize : MessageEncapsulatingTransportSize+elem.padding]
			rand.Read(crypt)

			// populate header fields
			headerOffset := MessageEncapsulatingTransportSize + int(elem.padding)
			header := elem.buffer[headerOffset : headerOffset+MessageTransportHeaderSize]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			// AmneziaWG H4: randomize the transport message type within its range.
			binary.LittleEndian.PutUint32(fieldType, device.headers.transport.Load().PickOne())
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

			contentOffset := headerOffset + MessageTransportHeaderSize
			contentSize := len(elem.packet)
			// Both AmneziaWG padding features size themselves against the full
			// on-the-wire message, not just its payload.
			wireSize := contentSize + MinMessageSize + int(elem.padding)
			mtu := int(device.tun.mtu.Load())

			paddingSize := elem.peer.randomPaddingAddition(wireSize)
			if paddingSize < 0 {
				// AmneziaWG random trailers on a transport message are applied
				// as content padding, so they stay inside the AEAD.
				paddingSize = elem.peer.randomTrailer(wireSize)
			}
			if paddingSize < 0 {
				// pad content to multiple of 16
				paddingSize = calculatePaddingSize(contentSize, mtu)
			}

			// Append trailing zeroes. The region is taken from elem.buffer
			// rather than grown from elem.packet, because a keepalive has a nil
			// packet and Seal encrypts in place at contentOffset either way.
			// Room is reserved for the tag Seal appends.
			if room := len(elem.buffer) - contentOffset - poly1305.TagSize - contentSize; paddingSize > room {
				paddingSize = room
				if paddingSize < 0 {
					paddingSize = 0
				}
			}
			elem.packet = elem.buffer[contentOffset : contentOffset+contentSize+paddingSize]
			for i := contentSize; i < len(elem.packet); i++ {
				elem.packet[i] = 0
			}

			// encrypt content and release to consumer

			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
			elem.packet = elem.keypair.send.Seal(
				elem.buffer[MessageEncapsulatingTransportSize:headerOffset+MessageTransportHeaderSize],
				nonce[:],
				elem.packet,
				nil,
			)

			cip, err := device.HeaderProtectionCipher(crypt)
			if err != nil {
				device.log.Errorf("Routine: header protection failed - packet dropped: %v", err)
				elem.packet = nil
				continue
			}
			if cip != nil {
				cip.XORKeyStream(header, header)
			}

			// re-slice packet to include encapsulating transport space
			elem.packet = elem.buffer[:MessageEncapsulatingTransportSize+len(elem.packet)]
		}
		elemsContainer.filling.Done()
	}
}

func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	device := peer.device
	defer func() {
		defer device.log.Verbosef("%v - Routine: sequential sender - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential sender - started", peer)

	bufs := make([][]byte, 0, max(maxBatchSize, conn.IdealBatchSize))

	for elemsContainer := range peer.queue.outbound.c {
		if elemsContainer == nil {
			return
		}
		peer.processOutboundContainer(elemsContainer, bufs[:0])
	}
}

// processOutboundContainer waits for the encryption routine to finish
// filling elemsContainer, then sends the batch (or drops it, if the peer
// has been stopped) and returns the container to the pool.
//
// scratch is a length-0 slice used to assemble the per-packet buffers
// passed to SendBuffers; its backing array is reused across calls.
func (peer *Peer) processOutboundContainer(elemsContainer *QueueOutboundElementsContainer, scratch [][]byte) {
	// Invariants from RoutineSequentialSender; all should be unreachable.
	if len(scratch) != 0 || cap(scratch) == 0 {
		panic(fmt.Sprintf("processOutboundContainer: scratch must be empty with non-zero cap; got len=%d cap=%d",
			len(scratch), cap(scratch)))
	}
	if cap(scratch) < len(elemsContainer.elems) {
		panic(fmt.Sprintf("processOutboundContainer: scratch cap %d < elems %d",
			cap(scratch), len(elemsContainer.elems)))
	}

	device := peer.device
	defer device.PutOutboundElementsContainer(elemsContainer)

	// Wait for RoutineEncryption to finish filling the container. After
	// Wait returns we have happens-before with that goroutine and are the
	// sole owner of the container until Put hands it back to the pool.
	elemsContainer.filling.Wait()

	if !peer.isRunning.Load() {
		// peer has been stopped; return re-usable elems to the shared pool.
		// This is an optimization only. It is possible for the peer to be stopped
		// immediately after this check, in which case, elem will get processed.
		// The timers and SendBuffers code are resilient to a few stragglers.
		// TODO: rework peer shutdown order to ensure
		// that we never accidentally keep timers alive longer than necessary.
		peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
		for _, elem := range elemsContainer.elems {
			device.PutOutboundBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		}
		return
	}

	dataSent := false
	for _, elem := range elemsContainer.elems {
		// A failure to apply AmneziaWG header protection drops the packet during
		// encryption and leaves elem.packet nil; skip those rather than slicing
		// them. The buffer is still returned to the pool below.
		if elem.packet == nil {
			continue
		}
		if !elem.isKeepalive {
			dataSent = true
		}
		scratch = append(scratch, elem.packet)
	}

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	err := peer.SendBuffers(scratch)
	if dataSent {
		peer.timersDataSent()
	}
	peer.queuedOutboundPackets.Add(-int32(len(elemsContainer.elems)))
	for _, elem := range elemsContainer.elems {
		device.PutOutboundBuffer(elem.buffer)
		device.PutOutboundElement(elem)
	}
	if err != nil {
		var errGSO conn.ErrUDPGSODisabled
		if errors.As(err, &errGSO) {
			device.log.Verbosef(err.Error())
			err = errGSO.RetryErr
		}
	}
	if err != nil {
		device.log.Errorf("%v - Failed to send data packets: %v", peer, err)
		return
	}

	peer.keepKeyFreshSending()
}
