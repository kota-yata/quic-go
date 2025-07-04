package wire

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/quic-go/quic-go/internal/protocol"
)

func TestObservedAddressFrame(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		addr := netip.MustParseAddrPort("192.168.1.1:8080")
		frame := &ObservedAddressFrame{
			SequenceNumber: 42,
			Address:        addr,
		}

		var buf bytes.Buffer
		data, err := frame.Append(buf.Bytes(), protocol.Version1)
		require.NoError(t, err)

		parsed, length, err := parseObservedAddressFrame(data[4:], 0x9f81a6, protocol.Version1) // skip frame type
		require.NoError(t, err)
		assert.Equal(t, len(data), length)
		assert.Equal(t, frame.SequenceNumber, parsed.SequenceNumber)
		assert.Equal(t, frame.Address, parsed.Address)
		assert.Equal(t, frame.Length(protocol.Version1), protocol.ByteCount(len(data)))
	})

	t.Run("IPv6", func(t *testing.T) {
		addr := netip.MustParseAddrPort("[2001:db8::1]:8080")
		frame := &ObservedAddressFrame{
			SequenceNumber: 123,
			Address:        addr,
		}

		var buf bytes.Buffer
		data, err := frame.Append(buf.Bytes(), protocol.Version1)
		require.NoError(t, err)

		parsed, length, err := parseObservedAddressFrame(data[4:], 0x9f81a6, protocol.Version1) // skip frame type
		require.NoError(t, err)
		assert.Equal(t, len(data), length)
		assert.Equal(t, frame.SequenceNumber, parsed.SequenceNumber)
		assert.Equal(t, frame.Address, parsed.Address)
		assert.Equal(t, frame.Length(protocol.Version1), protocol.ByteCount(len(data)))
	})

	t.Run("truncated frame", func(t *testing.T) {
		data := []byte{0x9f, 0x81, 0xa6, 0x2a} // frame type + partial sequence number
		_, _, err := parseObservedAddressFrame(data[4:], 0x9f81a6, protocol.Version1) // skip frame type
		assert.Error(t, err)
	})

	t.Run("invalid sequence number", func(t *testing.T) {
		data := []byte{0x9f, 0x81, 0xa6, 0xff, 0xff, 0xff, 0xff, 0xff} // invalid varint
		_, _, err := parseObservedAddressFrame(data[4:], 0x9f81a6, protocol.Version1) // skip frame type
		assert.Error(t, err)
	})

	t.Run("frame type determines IP version", func(t *testing.T) {
		// Test IPv4 frame type (0x9f81a6 encoded as varint)
		ipv4Addr := netip.MustParseAddrPort("10.0.0.1:80")
		ipv4Frame := &ObservedAddressFrame{
			SequenceNumber: 1,
			Address:        ipv4Addr,
		}
		ipv4Data, err := ipv4Frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		
		// Parse back to verify frame type
		parsed4, _, err := parseObservedAddressFrame(ipv4Data[4:], 0x9f81a6, protocol.Version1) // skip frame type
		require.NoError(t, err)
		assert.True(t, parsed4.Address.Addr().Is4())

		// Test IPv6 frame type (0x9f81a7 encoded as varint)
		ipv6Addr := netip.MustParseAddrPort("[::1]:80")
		ipv6Frame := &ObservedAddressFrame{
			SequenceNumber: 1,
			Address:        ipv6Addr,
		}
		ipv6Data, err := ipv6Frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		
		// Parse back to verify frame type
		parsed6, _, err := parseObservedAddressFrame(ipv6Data[4:], 0x9f81a7, protocol.Version1) // skip frame type
		require.NoError(t, err)
		assert.True(t, parsed6.Address.Addr().Is6())
	})
}

func TestObservedAddressFrameLength(t *testing.T) {
	t.Run("IPv4 length", func(t *testing.T) {
		addr := netip.MustParseAddrPort("1.2.3.4:80")
		frame := &ObservedAddressFrame{
			SequenceNumber: 1,
			Address:        addr,
		}
		
		// Test actual length by marshaling and checking
		data, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		assert.Equal(t, protocol.ByteCount(len(data)), frame.Length(protocol.Version1))
	})

	t.Run("IPv6 length", func(t *testing.T) {
		addr := netip.MustParseAddrPort("[::1]:80")
		frame := &ObservedAddressFrame{
			SequenceNumber: 1,
			Address:        addr,
		}
		
		// Test actual length by marshaling and checking
		data, err := frame.Append(nil, protocol.Version1)
		require.NoError(t, err)
		assert.Equal(t, protocol.ByteCount(len(data)), frame.Length(protocol.Version1))
	})
}