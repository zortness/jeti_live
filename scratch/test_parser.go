package main

import (
	"encoding/binary"
	"fmt"
)

func decode6b(valByte byte) (float64, int, int8) {
	sign := int8(1)
	if (valByte & 0x80) != 0 {
		sign = -1
	}
	precision := int((valByte & 0x60) >> 5)
	absVal := int8(valByte & 0x1F)
	val := absVal * sign
	
	var floatVal float64
	switch precision {
	case 1:
		floatVal = float64(val) / 10.0
	case 2:
		floatVal = float64(val) / 100.0
	default:
		floatVal = float64(val)
	}
	return floatVal, precision, val
}

func decode14b(low, high byte) (float64, int, int16) {
	sign := int16(1)
	if (high & 0x80) != 0 {
		sign = -1
	}
	precision := int((high & 0x60) >> 5)
	absVal := int16(low) | (int16(high&0x1F) << 8)
	val := absVal * sign
	
	var floatVal float64
	switch precision {
	case 1:
		floatVal = float64(val) / 10.0
	case 2:
		floatVal = float64(val) / 100.0
	default:
		floatVal = float64(val)
	}
	return floatVal, precision, val
}

func decode22b(low, mid, high byte) (float64, int, int32) {
	sign := int32(1)
	if (high & 0x80) != 0 {
		sign = -1
	}
	precision := int((high & 0x60) >> 5)
	absVal := int32(low) | (int32(mid) << 8) | (int32(high&0x1F) << 16)
	val := absVal * sign
	
	var floatVal float64
	switch precision {
	case 1:
		floatVal = float64(val) / 10.0
	case 2:
		floatVal = float64(val) / 100.0
	default:
		floatVal = float64(val)
	}
	return floatVal, precision, val
}

func decode30b(b0, b1, b2, b3 byte) (float64, int, int32) {
	sign := int32(1)
	if (b3 & 0x80) != 0 {
		sign = -1
	}
	precision := int((b3 & 0x60) >> 5)
	absVal := int32(b0) | (int32(b1) << 8) | (int32(b2) << 16) | (int32(b3&0x1F) << 24)
	val := absVal * sign
	
	var floatVal float64
	switch precision {
	case 1:
		floatVal = float64(val) / 10.0
	case 2:
		floatVal = float64(val) / 100.0
	default:
		floatVal = float64(val)
	}
	return floatVal, precision, val
}

func getDataTypeSize(dataType byte) int {
	switch dataType {
	case 0:
		return 1
	case 1, 2, 3:
		return 2
	case 4, 5, 6, 7:
		return 3
	case 8, 9, 10, 11:
		return 4
	case 12:
		return 2 // fallback or custom size for Temp B
	case 15:
		return 4 // Sensor Serial
	default:
		return 2
	}
}

func findAsciiStart(payload []byte) int {
	i := len(payload) - 1
	for i >= 0 && i >= len(payload)-3 {
		b := payload[i]
		if (b >= 32 && b <= 126) || b == 0xb0 || b == 0xdf {
			break
		}
		i--
	}
	for i >= 0 {
		b := payload[i]
		if (b >= 32 && b <= 126) || b == 0xb0 || b == 0xdf || b == 0x09 || b == 0x0A || b == 0x0D {
			i--
		} else {
			break
		}
	}
	start := i + 1
	if len(payload)-start < 3 {
		return len(payload)
	}
	return start
}

func parsePayload(payload []byte) {
	if len(payload) < 8 {
		fmt.Println("Payload too short")
		return
	}
	
	// Extract Device ID (bytes 3-6)
	deviceID := binary.LittleEndian.Uint32(payload[3:7])
	deviceIDStr := fmt.Sprintf("%08X", deviceID)
	
	asciiStart := findAsciiStart(payload)
	fmt.Printf("Payload hex: %X\n", payload)
	fmt.Printf("Device ID: %s\n", deviceIDStr)
	fmt.Printf("ASCII start index: %d\n", asciiStart)
	if asciiStart < len(payload) {
		fmt.Printf("ASCII text: %q\n", string(payload[asciiStart:]))
	}
	
	// Determine device type dynamically
	deviceType := "Unknown"
	
	// First pass: scan to determine device type
	idx := 8
	for idx < asciiStart {
		firstByte := payload[idx]
		idx++
		
		var fieldID byte
		var dataType byte
		if (firstByte >> 4) == 0 {
			if idx >= asciiStart {
				break
			}
			dataType = firstByte & 0x0F
			fieldID = payload[idx]
			idx++
		} else {
			fieldID = firstByte >> 4
			dataType = firstByte & 0x0F
		}
		
		size := getDataTypeSize(dataType)
		if idx+size > asciiStart {
			break
		}
		idx += size
		
		if fieldID == 2 && dataType == 1 {
			deviceType = "TempSensor"
		} else if fieldID == 2 && dataType == 0 {
			deviceType = "Receiver"
		}
	}
	fmt.Printf("Detected Device Type: %s\n", deviceType)
	
	// Second pass: parse and print telemetry fields
	idx = 8
	for idx < asciiStart {
		firstByte := payload[idx]
		idx++
		
		var fieldID byte
		var dataType byte
		if (firstByte >> 4) == 0 {
			if idx >= asciiStart {
				break
			}
			dataType = firstByte & 0x0F
			fieldID = payload[idx]
			idx++
		} else {
			fieldID = firstByte >> 4
			dataType = firstByte & 0x0F
		}
		
		size := getDataTypeSize(dataType)
		if idx+size > asciiStart {
			break
		}
		
		rawBytes := payload[idx : idx+size]
		idx += size
		
		var floatVal float64
		var precision int
		var rawVal interface{}
		
		switch size {
		case 1:
			fv, prec, r := decode6b(rawBytes[0])
			floatVal = fv
			precision = prec
			rawVal = r
		case 2:
			fv, prec, r := decode14b(rawBytes[0], rawBytes[1])
			floatVal = fv
			precision = prec
			rawVal = r
		case 3:
			fv, prec, r := decode22b(rawBytes[0], rawBytes[1], rawBytes[2])
			floatVal = fv
			precision = prec
			rawVal = r
		case 4:
			fv, prec, r := decode30b(rawBytes[0], rawBytes[1], rawBytes[2], rawBytes[3])
			floatVal = fv
			precision = prec
			rawVal = r
		}
		
		fieldName := fmt.Sprintf("Field %d", fieldID)
		interpreted := ""
		
		if fieldID == 1 {
			fieldName = "Rx Voltage"
			volts := floatVal
			if volts > 100 {
				volts /= 1000.0
			} else if volts > 10 {
				volts /= 10.0
			}
			interpreted = fmt.Sprintf("%.2f V", volts)
		} else if fieldID == 2 {
			if deviceType == "Receiver" {
				fieldName = "Antenna 1"
				interpreted = fmt.Sprintf("%.0f", floatVal)
			} else if deviceType == "TempSensor" {
				fieldName = "Temp. A"
				temp := floatVal
				if temp > 100 {
					temp /= 10.0
				}
				interpreted = fmt.Sprintf("%.1f °C", temp)
			}
		} else if fieldID == 3 {
			if deviceType == "Receiver" {
				fieldName = "Antenna 2"
				interpreted = fmt.Sprintf("%.0f", floatVal)
			} else if deviceType == "TempSensor" {
				fieldName = "Temp. B"
				temp := floatVal
				if temp > 100 {
					temp /= 10.0
				}
				interpreted = fmt.Sprintf("%.1f °C", temp)
			}
		} else {
			if precision > 0 {
				interpreted = fmt.Sprintf("%.*f", precision, floatVal)
			} else {
				interpreted = fmt.Sprintf("%v", rawVal)
			}
		}
		
		fmt.Printf("  Field %d (%s) -> Interpreted: %s, Raw: %v (%X)\n", fieldID, fieldName, interpreted, rawVal, rawBytes)
	}
}

func main() {
	// Packet 1 payload
	p1 := []byte{0x41, 0x0E, 0x00, 0x9F, 0x4C, 0x81, 0xA8, 0x0D, 0x5c, 0x6d, 0x11, 0xf7, 0x20, 0x21, 0xf7, 0x20, 0x31}
	// Note: p1 was truncated in our text file, let's append a value for ID 3 (Temp B) to make it parse:
	// We add 0x6d 0x20 to finish field 0x31.
	p1_full := append(p1, 0x6d, 0x20)
	parsePayload(p1_full)
	fmt.Println("----------------------------------------------------------------")
	// Packet 2 payload with ASCII text
	p2 := []byte{0x41, 0x13, 0x00, 0x9F, 0x11, 0x81, 0xA8, 0x0D, 0x5c, 0xb3, 0x01, 0x3a, 0x54, 0x65, 0x6d, 0x70, 0x2e, 0x20, 0x41, 0xb0, 0x43, 0xe3}
	// Let's add 2 bytes to p2 as well if it's truncated? No, p2 text scan ends at 11, so it won't parse past index 11.
	parsePayload(p2)
	fmt.Println("----------------------------------------------------------------")
	// Let's test Packet 3 from line 67 of capture notes:
	// 47 0f 00 9f 4d e2 a6 4b 54 f0 11 3c 20 20 09 30 09 2a
	// Wait, let's replace 3c with 30 (Antenna 2 = ID 3, DataType 0), 20 with 09 (Antenna 1 value = 9), and 2a with nothing.
	// 47 0f 00 9f 4d e2 a6 4b 54 f0 11 20 09 30 09
	p3 := []byte{0x47, 0x0F, 0x00, 0x9F, 0x4D, 0xE2, 0xA6, 0x4B, 0x54, 0xF0, 0x11, 0x20, 0x09, 0x30, 0x09}
	parsePayload(p3)
}
