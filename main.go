package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"jeti_live/jeti"

	"go.bug.st/serial"
)

type TelemetryField struct {
	FieldID    byte
	FieldName  string
	Value      string
	Unit       string
	LastUpdate time.Time
}

type DeviceState struct {
	DeviceName string
	Fields     map[byte]TelemetryField
}

type DashboardState struct {
	mu           sync.Mutex
	Connected    bool
	BaudRate     int
	PortName     string
	DeviceID     string
	DisplayLines [2]string
	Devices      map[uint32]*DeviceState // key: physicalPrefix (DeviceID >> 8)
}

func newDashboardState(port string, baud int) *DashboardState {
	return &DashboardState{
		PortName: port,
		BaudRate: baud,
		Devices:  make(map[uint32]*DeviceState),
		DeviceID: "Searching...",
	}
}

func (s *DashboardState) UpdateConnection(connected bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Connected = connected
}

func (s *DashboardState) UpdateDeviceID(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DeviceID = id
}

func (s *DashboardState) UpdateDisplay(lines [2]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if lines[0] != "" {
		s.DisplayLines[0] = lines[0]
	}
	if lines[1] != "" {
		s.DisplayLines[1] = lines[1]
	}
}

func (s *DashboardState) UpdateValue(physicalPrefix uint32, fieldID byte, val string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, exists := s.Devices[physicalPrefix]
	if !exists {
		dev = &DeviceState{
			Fields: make(map[byte]TelemetryField),
		}
		s.Devices[physicalPrefix] = dev
	}
	field, exists := dev.Fields[fieldID]
	if !exists {
		field = TelemetryField{
			FieldID: fieldID,
		}
	}
	field.Value = val
	field.LastUpdate = time.Now()
	if field.FieldName == "" {
		field.FieldName = fmt.Sprintf("Field %d", fieldID)
	}
	dev.Fields[fieldID] = field
}

func (s *DashboardState) UpdateFieldMeta(physicalPrefix uint32, fieldID byte, name string, unit string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, exists := s.Devices[physicalPrefix]
	if !exists {
		dev = &DeviceState{
			Fields: make(map[byte]TelemetryField),
		}
		s.Devices[physicalPrefix] = dev
	}
	if fieldID == 0 {
		dev.DeviceName = name
		return
	}
	field, exists := dev.Fields[fieldID]
	if !exists {
		field = TelemetryField{
			FieldID: fieldID,
		}
	}
	field.FieldName = name
	field.Unit = unit
	dev.Fields[fieldID] = field
}

func drawDashboard(state *DashboardState) {
	state.mu.Lock()
	defer state.mu.Unlock()

	// Move cursor to top-left (without clearing screen to prevent flicker)
	fmt.Print("\033[H")

	fmt.Println("\033[1;36m==============================================================\033[K")
	fmt.Println("                 JETI TELEMETRY LIVE INSPECTOR\033[K")
	fmt.Println("==============================================================\033[K\033[0m")

	// Print connection status
	status := "\033[1;31mDISCONNECTED\033[0m"
	if state.Connected {
		status = fmt.Sprintf("\033[1;32mCONNECTED\033[0m (%s @ %d baud)", state.PortName, state.BaudRate)
	}
	fmt.Printf("Status: %s\033[K\n", status)
	fmt.Printf("Device: \033[1;35m%s\033[0m\033[K\n", state.DeviceID)
	fmt.Println("\033[K")

	// Print JetiBox Display Screen
	fmt.Println("\033[1;33m+----------------------------------+\033[K")
	fmt.Printf("| %-32s |\033[K\n", state.DisplayLines[0])
	fmt.Printf("| %-32s |\033[K\n", state.DisplayLines[1])
	fmt.Println("+----------------------------------+\033[K\033[0m")
	fmt.Println("\033[K")

	// Print Telemetry parameters table
	fmt.Println("\033[1mDetected Telemetry Fields (Grouped by Device):\033[K\033[0m")
	fmt.Println("--------------------------------------------------------------\033[K")

	if len(state.Devices) == 0 {
		fmt.Println("  (Waiting for telemetry data...)\033[K")
	} else {
		// Sort physical prefixes for consistent display
		var prefixes []uint32
		for prefix := range state.Devices {
			prefixes = append(prefixes, prefix)
		}
		sort.Slice(prefixes, func(i, j int) bool {
			return prefixes[i] < prefixes[j]
		})

		for _, prefix := range prefixes {
			dev := state.Devices[prefix]
			devName := dev.DeviceName
			if devName == "" {
				// Default mappings if we don't have the text registration name yet
				switch prefix {
				case 0x4BA6E2:
					devName = "Receiver"
				case 0x0DA881:
					devName = "MT-125"
				default:
					devName = fmt.Sprintf("Device %06X", prefix)
				}
			}
			fmt.Printf("\033[1;35m>>> %s (Serial Prefix: 0x%06X)\033[0m\033[K\n", devName, prefix)
			fmt.Printf("    %-10s | %-15s | %-20s | %-12s\033[K\n", "Field ID", "Field Name", "Value", "Last Update")
			fmt.Println("    ----------------------------------------------------------\033[K")

			// Sort field IDs
			var fieldIDs []byte
			for fid := range dev.Fields {
				fieldIDs = append(fieldIDs, fid)
			}
			sort.Slice(fieldIDs, func(i, j int) bool {
				return fieldIDs[i] < fieldIDs[j]
			})

			for _, fid := range fieldIDs {
				f := dev.Fields[fid]
				timeStr := f.LastUpdate.Format("15:04:05.000")
				unitSuffix := ""
				if f.Unit != "" {
					unitSuffix = " " + f.Unit
				}
				valPrint := f.Value + unitSuffix
				fmt.Printf("    0x%02X       | %-15s | \033[1;32m%-20s\033[0m | %-12s\033[K\n", fid, f.FieldName, valPrint, timeStr)
			}
			fmt.Println("--------------------------------------------------------------\033[K")
		}
	}
	fmt.Println("\nPress Ctrl+C to exit.\033[K")
}

func main() {
	portFlag := flag.String("port", "COM17", "Serial port to connect to")
	baudFlag := flag.Int("baud", 250000, "Baud rate")
	flag.Parse()

	state := newDashboardState(*portFlag, *baudFlag)

	// Set up serial mode
	mode := &serial.Mode{
		BaudRate: *baudFlag,
		Parity:   serial.NoParity,
		DataBits: 8,
		StopBits: serial.OneStopBit,
	}

	fmt.Printf("Opening port %s...\n", *portFlag)
	port, err := serial.Open(*portFlag, mode)
	if err != nil {
		log.Fatalf("Failed to open port: %v", err)
	}
	defer port.Close()

	// Configure modem control signals (DTR=True, RTS=False)
	if err := port.SetDTR(true); err != nil {
		fmt.Printf("Warning: Failed to set DTR: %v\n", err)
	}
	if err := port.SetRTS(false); err != nil {
		fmt.Printf("Warning: Failed to set RTS: %v\n", err)
	}

	state.UpdateConnection(true)

	// Clean input buffer
	port.ResetInputBuffer()

	// Channel to signal shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Mutex protected write
	var writeMu sync.Mutex
	sendPacket := func(subID byte, cmdType byte, payload []byte) {
		writeMu.Lock()
		defer writeMu.Unlock()

		header := []byte{0x3E, 0x02}
		length := 2 + 1 + 1 + 1 + 1 + len(payload) + 2
		pktData := append(header, byte(length), 0x00, subID, cmdType)
		pktData = append(pktData, payload...)
		crc := jeti.Crc16Ref(pktData)
		pktData = append(pktData, byte(crc&0xFF), byte(crc>>8))

		port.Write(pktData)
	}

	// 1. Send Handshake Ping (SubID=0x0E, Cmd=0x02)
	sendPacket(0x0E, 0x02, nil)

	// Telemetry reader buffer
	var rxBuffer []byte
	var rxMu sync.Mutex

	// Read loop
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := port.Read(buf)
			if err != nil {
				state.UpdateConnection(false)
				return
			}
			if n > 0 {
				rxMu.Lock()
				rxBuffer = append(rxBuffer, buf[:n]...)
				
				// Parse all complete packets
				for {
					pkt, consumed, err := jeti.ParseDevicePacket(rxBuffer)
					if err != nil {
						// Drop invalid bytes and search again
						rxBuffer = rxBuffer[consumed:]
						continue
					}
					if pkt == nil {
						// Incomplete packet, wait for more data
						break
					}
					rxBuffer = rxBuffer[consumed:]

					// Handle packet data
					switch pkt.CmdType {
					case 0x02:
						state.UpdateDeviceID(strings.TrimSpace(string(pkt.Payload)))
					case 0x30:
						parseTelemetry(state, pkt.Payload)

						// Decode screen lines (only from the suffix after the EX packet)
						if len(pkt.Payload) >= 2 {
							exLength := int(pkt.Payload[1] & 0x3F)
							textStart := 2 + exLength + 1
							if textStart < len(pkt.Payload) {
								var printable []string
								var current []byte
								for _, b := range pkt.Payload[textStart:] {
									if (b >= 32 && b <= 126) || b == 0xb0 || b == 0xdf {
										current = append(current, b)
									} else {
										if len(current) >= 3 {
											printable = append(printable, strings.TrimSpace(string(current)))
										}
										current = nil
									}
								}
								if len(current) >= 3 {
									printable = append(printable, strings.TrimSpace(string(current)))
								}
								
								var lines [2]string
								if len(printable) >= 2 {
									lines[0] = printable[0]
									lines[1] = printable[1]
								} else if len(printable) == 1 {
									lines[0] = printable[0]
								}
								state.UpdateDisplay(lines)
							}
						}
						
					case 0x00:
						parseTelemetry(state, pkt.Payload)
					}
				}
				rxMu.Unlock()
			}
		}
	}()

	// Parameter registration sender
	go func() {
		time.Sleep(500 * time.Millisecond)
		// Register parameters 41, 42, 45, 47
		regPayload := []byte{
			0x41, 0x01, 0x00, 0x01,
			0x42, 0x01, 0x00, 0x01,
			0x45, 0x01, 0x00, 0x01,
			0x47, 0x01, 0x00, 0x01,
		}
		sendPacket(0x0F, 0x16, regPayload)
	}()

	// Polling loop (every 2 seconds)
	go func() {
		var seq byte = 7
		for {
			time.Sleep(2 * time.Second)
			seq = (seq % 15) + 1
			sendPacket(seq, 0x02, nil)
		}
	}()

	// Dashboard renderer loop (every 150ms)
	done := make(chan bool)
	go func() {
		// Clear screen once on startup
		fmt.Print("\033[H\033[2J")
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				drawDashboard(state)
			}
		}
	}()

	// Wait for Ctrl+C
	<-sigChan
	done <- true
	fmt.Println("\nExiting Jeti inspector...")
}

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
		return 1 // climb / vario / custom 1-byte field
	case 15:
		return 4 // Sensor Serial
	default:
		return 2
	}
}

func parseTelemetry(state *DashboardState, payload []byte) {
	if len(payload) < 2 {
		return
	}
	exLength := int(payload[1] & 0x3F)
	if len(payload) < 2+exLength {
		return
	}

	// Product ID is 2 bytes (bytes 2-3), Device ID is 4 bytes (bytes 4-7)
	if len(payload) < 8 {
		return
	}
	devID := binary.LittleEndian.Uint32(payload[4:8])
	physicalPrefix := devID >> 8

	// Differentiate Text packets (exLength >= 16) and Data packets (exLength <= 15)
	if exLength <= 15 {
		idx := 8
		endIdx := 2 + exLength
		for idx < endIdx {
			firstByte := payload[idx]
			idx++

			fieldID := firstByte >> 4
			dataType := firstByte & 0x0F

			size := getDataTypeSize(dataType)
			if fieldID == 5 && dataType == 4 {
				size = 2 // override quirk: Field 5 DataType 4 is 2 bytes in Jeti receiver
			}

			if idx+size > endIdx {
				break
			}

			rawBytes := payload[idx : idx+size]
			idx += size

			var floatVal float64
			var precision int

			switch size {
			case 1:
				fv, prec, _ := decode6b(rawBytes[0])
				floatVal = fv
				precision = prec
			case 2:
				fv, prec, _ := decode14b(rawBytes[0], rawBytes[1])
				floatVal = fv
				precision = prec
			case 3:
				fv, prec, _ := decode22b(rawBytes[0], rawBytes[1], rawBytes[2])
				floatVal = fv
				precision = prec
			case 4:
				fv, prec, _ := decode30b(rawBytes[0], rawBytes[1], rawBytes[2], rawBytes[3])
				floatVal = fv
				precision = prec
			}

			var valStr string
			if fieldID == 5 && dataType == 4 {
				// Rx Voltage (Field 5 DataType 4 is scaled in millivolts)
				valStr = fmt.Sprintf("%.2f", floatVal/1000.0)
			} else {
				if precision > 0 {
					valStr = fmt.Sprintf("%.*f", precision, floatVal)
				} else {
					valStr = fmt.Sprintf("%.0f", floatVal)
				}
			}

			state.UpdateValue(physicalPrefix, fieldID, valStr)
		}
	} else {
		// Text packet: text label definitions start at index 10
		idx := 10
		endIdx := 2 + exLength
		if idx+2 <= endIdx {
			fieldID := payload[idx]
			idx++
			lengths := payload[idx]
			idx++
			descLen := int(lengths >> 3)
			unitLen := int(lengths & 0x07)

			if idx+descLen+unitLen <= endIdx {
				descBytes := payload[idx : idx+descLen]
				idx += descLen
				unitBytes := payload[idx : idx+unitLen]

				descStr := strings.TrimSpace(string(descBytes))
				unitStr := strings.TrimSpace(string(unitBytes))

				state.UpdateFieldMeta(physicalPrefix, fieldID, descStr, unitStr)
			}
		}
	}
}
