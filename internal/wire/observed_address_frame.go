package wire

import (
	"encoding/binary"
	"io"
	"net/netip"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// An ObservedAddressFrame is an OBSERVED_ADDRESS frame
type ObservedAddressFrame struct {
	SequenceNumber uint64
	Address        netip.AddrPort
}

func parseObservedAddressFrame(b []byte, typ FrameType, _ protocol.Version) (*ObservedAddressFrame, int, error) {
	startLen := len(b)
	// fmt.Printf("DEBUG: parseObservedAddressFrame called with %d bytes: %x, frameType: %x\n", len(b), b, typ)

	// Check if it's IPv4 (0x9f81a6) or IPv6 (0x9f81a7)
	isIPv4 := typ == 0x9f81a6

	// Parse sequence number
	sequenceNumber, bytesRead, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, err
	}
	b = b[bytesRead:]

	var addr netip.Addr
	var port uint16

	if isIPv4 {
		// Parse IPv4 address (4 bytes)
		if len(b) < 4 {
			return nil, 0, io.EOF
		}
		ipv4Bytes := [4]byte{}
		copy(ipv4Bytes[:], b[:4])
		addr = netip.AddrFrom4(ipv4Bytes)
		b = b[4:]
	} else {
		// Parse IPv6 address (16 bytes)
		if len(b) < 16 {
			return nil, 0, io.EOF
		}
		ipv6Bytes := [16]byte{}
		copy(ipv6Bytes[:], b[:16])
		addr = netip.AddrFrom16(ipv6Bytes)
		b = b[16:]
	}

	// Parse port (2 bytes, network byte order)
	if len(b) < 2 {
		return nil, 0, io.EOF
	}
	port = binary.BigEndian.Uint16(b[:2])

	return &ObservedAddressFrame{
		SequenceNumber: sequenceNumber,
		Address:        netip.AddrPortFrom(addr, port),
	}, startLen - len(b) + 2, nil
}

func (f *ObservedAddressFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	// Determine frame type based on address type
	var frameType uint64
	if f.Address.Addr().Is4() {
		frameType = 0x9f81a6
	} else {
		frameType = 0x9f81a7
	}

	// fmt.Printf("DEBUG: Creating OBSERVED_ADDRESS frame for %s, seq=%d\n", f.Address, f.SequenceNumber)

	// Append frame type
	b = quicvarint.Append(b, frameType)

	// Append sequence number
	b = quicvarint.Append(b, f.SequenceNumber)

	// Append address
	if f.Address.Addr().Is4() {
		ipv4 := f.Address.Addr().As4()
		b = append(b, ipv4[:]...)
	} else {
		ipv6 := f.Address.Addr().As16()
		b = append(b, ipv6[:]...)
	}

	// Append port in network byte order
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, f.Address.Port())
	b = append(b, portBytes...)

	// fmt.Printf("DEBUG: OBSERVED_ADDRESS frame created, total length: %d bytes\n", len(b))
	return b, nil
}

// Length of a written frame
func (f *ObservedAddressFrame) Length(_ protocol.Version) protocol.ByteCount {
	length := quicvarint.Len(0x9f81a6) + quicvarint.Len(f.SequenceNumber) + 2 // frame type + sequence number + port
	if f.Address.Addr().Is4() {
		length += 4 // IPv4 address
	} else {
		length += 16 // IPv6 address
	}
	return protocol.ByteCount(length)
}
