package jeti

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Packet represents a parsed Jeti protocol packet
type Packet struct {
	Seq     byte
	SubID   byte
	CmdType byte
	Payload []byte
	Raw     []byte
}

// ParseDevicePacket scans a buffer for a valid device response packet (starting with '<' 0x3C, 0x02)
// Returns:
//   - *Packet: the parsed packet if successful, nil otherwise
//   - int: the number of bytes consumed from rxBuffer (to advance the buffer)
//   - error: any parsing or CRC error encountered
func ParseDevicePacket(rxBuffer []byte) (*Packet, int, error) {
	pos := bytes.Index(rxBuffer, []byte{0x3C, 0x02})
	if pos == -1 {
		// No STX found, but keep the last 1 byte in case it's a split 0x3C
		if len(rxBuffer) > 0 {
			return nil, len(rxBuffer) - 1, nil
		}
		return nil, 0, nil
	}

	if len(rxBuffer) < pos+4 {
		return nil, pos, nil // Wait for more data to read length
	}

	length := int(rxBuffer[pos+2])
	if length < 6 {
		// Invalid packet length, discard the STX prefix and search again
		return nil, pos + 1, nil
	}

	if len(rxBuffer) < pos+length {
		return nil, pos, nil // Packet incomplete, wait for more data
	}

	pktBytes := rxBuffer[pos : pos+length]

	// Verify CRC
	dataToCheck := pktBytes[:length-2]
	expectedCRC := binary.LittleEndian.Uint16(pktBytes[length-2:])
	actualCRC := Crc16Ref(dataToCheck)

	if expectedCRC != actualCRC {
		return nil, pos + 1, fmt.Errorf("CRC failed: expected %04X, calculated %04X", expectedCRC, actualCRC)
	}

	pkt := &Packet{
		Seq:     pktBytes[3],
		SubID:   pktBytes[4],
		CmdType: pktBytes[5],
		Payload: make([]byte, length-8),
		Raw:     pktBytes,
	}
	copy(pkt.Payload, pktBytes[6:length-2])

	return pkt, pos + length, nil
}

// Decode translates the payload bytes into a human-readable description
func (p *Packet) Decode() string {
	switch p.CmdType {
	case 0x02:
		// Device Identification String
		return fmt.Sprintf("Device ID String: %q", strings.TrimSpace(string(p.Payload)))
		
	case 0x30:
		// Telemetry Display Line (ASCII and status)
		var printable []string
		var current bytes.Buffer
		for _, b := range p.Payload {
			if (b >= 32 && b <= 126) || (b >= 160 && b <= 255) {
				current.WriteByte(b)
			} else {
				if current.Len() >= 3 {
					printable = append(printable, strings.TrimSpace(current.String()))
				}
				current.Reset()
			}
		}
		if current.Len() >= 3 {
			printable = append(printable, strings.TrimSpace(current.String()))
		}
		
		desc := ""
		if len(printable) > 0 {
			desc += fmt.Sprintf("Display Screen: %s | ", strings.Join(printable, " / "))
		}
		desc += fmt.Sprintf("Raw Hex: %X", p.Payload)
		return desc
		
	case 0x00:
		// Telemetry Data Block (binary)
		var vals []string
		for i := 0; i+4 <= len(p.Payload); i += 4 {
			val := int32(binary.LittleEndian.Uint32(p.Payload[i : i+4]))
			// Parse negative numbers (e.g. RSSI dBm values like -43)
			vals = append(vals, fmt.Sprintf("%d", val))
		}
		return fmt.Sprintf("Telemetry values: [%s] | Raw Hex: %X", strings.Join(vals, ", "), p.Payload)
		
	default:
		return fmt.Sprintf("Type: %02X | Payload Hex: %X", p.CmdType, p.Payload)
	}
}
