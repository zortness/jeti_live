package main

import (
	"bufio"
	"encoding/binary"
	"encoding/csv"
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

type CSVColumn struct {
	PhysicalPrefix uint32
	FieldID        byte
	HeaderName     string
}

type DashboardState struct {
	mu           sync.Mutex
	Connected    bool
	BaudRate     int
	PortName     string
	DeviceID     string
	DisplayLines [2]string
	Devices      map[uint32]*DeviceState // key: physicalPrefix (DeviceID >> 8)

	// CSV Logging State
	LogEnabled       bool
	LogInterval      time.Duration
	LogDelay         time.Duration
	LogFileSetting   string
	LogActive        bool
	LogDelayActive   bool
	LogDelayEndTime  time.Time
	LogFileName      string
	LogColumns       []CSVColumn
	logFile          *os.File
	logWriter        *csv.Writer
	logTicker        *time.Ticker
	logDone          chan bool
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

func applyFallbacks(dev *DeviceState, physicalPrefix uint32) {
	name := dev.DeviceName
	if name == "" {
		switch physicalPrefix {
		case 0x4BA6E2, 0x6FA6E2:
			name = "Receiver"
		case 0x0DA881:
			name = "MT-125"
		}
	}

	nameLower := strings.ToLower(name)
	if strings.Contains(nameLower, "mui") {
		if f1, ok := dev.Fields[1]; ok {
			if f1.FieldName == "" || strings.HasPrefix(f1.FieldName, "Field ") {
				f1.FieldName = "Voltage"
				f1.Unit = "V"
				dev.Fields[1] = f1
			}
		}
		if f2, ok := dev.Fields[2]; ok {
			if f2.FieldName == "" || strings.HasPrefix(f2.FieldName, "Field ") {
				f2.FieldName = "Current"
				f2.Unit = "A"
				dev.Fields[2] = f2
			}
		}
		if f3, ok := dev.Fields[3]; ok {
			if f3.FieldName == "" || strings.HasPrefix(f3.FieldName, "Field ") {
				f3.FieldName = "Capacity"
				f3.Unit = "mAh"
				dev.Fields[3] = f3
			}
		}
		if f4, ok := dev.Fields[4]; ok {
			if f4.FieldName == "" || strings.HasPrefix(f4.FieldName, "Field ") {
				f4.FieldName = "Run time"
				f4.Unit = "s"
				dev.Fields[4] = f4
			}
		}
	} else if strings.Contains(nameLower, "receiver") || physicalPrefix == 0x4BA6E2 || physicalPrefix == 0x6FA6E2 {
		if f1, ok := dev.Fields[1]; ok {
			if f1.FieldName == "" || strings.HasPrefix(f1.FieldName, "Field ") {
				f1.FieldName = "Voltage RX"
				f1.Unit = "V"
				dev.Fields[1] = f1
			}
		}
		if f2, ok := dev.Fields[2]; ok {
			if f2.FieldName == "" || strings.HasPrefix(f2.FieldName, "Field ") {
				f2.FieldName = "Antenna 1"
				dev.Fields[2] = f2
			}
		}
		if f3, ok := dev.Fields[3]; ok {
			if f3.FieldName == "" || strings.HasPrefix(f3.FieldName, "Field ") {
				f3.FieldName = "Antenna 2"
				dev.Fields[3] = f3
			}
		}
	} else if strings.Contains(nameLower, "mt-125") || physicalPrefix == 0x0DA881 {
		if f1, ok := dev.Fields[1]; ok {
			if f1.FieldName == "" || strings.HasPrefix(f1.FieldName, "Field ") {
				f1.FieldName = "Temp A"
				f1.Unit = "°C"
				dev.Fields[1] = f1
			}
		}
		if f2, ok := dev.Fields[2]; ok {
			if f2.FieldName == "" || strings.HasPrefix(f2.FieldName, "Field ") {
				f2.FieldName = "Temp B"
				f2.Unit = "°C"
				dev.Fields[2] = f2
			}
		}
	}
}

func getCSVHeaderName(prefix uint32, devName string, field TelemetryField) string {
	devClean := devName
	if devClean == "" {
		switch prefix {
		case 0x4BA6E2, 0x6FA6E2:
			devClean = "Receiver"
		case 0x0DA881:
			devClean = "MT-125"
		default:
			devClean = fmt.Sprintf("Device_%06X", prefix)
		}
	}
	devClean = strings.ReplaceAll(devClean, " ", "_")
	fieldClean := strings.ReplaceAll(field.FieldName, " ", "_")
	return fmt.Sprintf("%s_%06X_F%d_%s", devClean, prefix, field.FieldID, fieldClean)
}

func (s *DashboardState) updateCSVColumnHeader(prefix uint32, fieldID byte, devName string, field TelemetryField) {
	for i, col := range s.LogColumns {
		if col.PhysicalPrefix == prefix && col.FieldID == fieldID {
			s.LogColumns[i].HeaderName = getCSVHeaderName(prefix, devName, field)
			break
		}
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

	applyFallbacks(dev, physicalPrefix)

	// Dynamically append new CSV column if logging is active
	if s.LogActive {
		found := false
		for _, col := range s.LogColumns {
			if col.PhysicalPrefix == physicalPrefix && col.FieldID == fieldID {
				found = true
				break
			}
		}
		if !found {
			if updatedField, ok := dev.Fields[fieldID]; ok {
				col := CSVColumn{
					PhysicalPrefix: physicalPrefix,
					FieldID:        fieldID,
					HeaderName:     getCSVHeaderName(physicalPrefix, dev.DeviceName, updatedField),
				}
				s.LogColumns = append(s.LogColumns, col)
			}
		}
	}
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
		applyFallbacks(dev, physicalPrefix)

		// Update headers for all columns of this device prefix
		for i, col := range s.LogColumns {
			if col.PhysicalPrefix == physicalPrefix {
				if f, ok := dev.Fields[col.FieldID]; ok {
					s.LogColumns[i].HeaderName = getCSVHeaderName(physicalPrefix, name, f)
				}
			}
		}
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

	applyFallbacks(dev, physicalPrefix)

	// Dynamically update column header
	if f, ok := dev.Fields[fieldID]; ok {
		s.updateCSVColumnHeader(physicalPrefix, fieldID, dev.DeviceName, f)
	}

	// Dynamically append new CSV column if logging is active
	if s.LogActive {
		found := false
		for _, col := range s.LogColumns {
			if col.PhysicalPrefix == physicalPrefix && col.FieldID == fieldID {
				found = true
				break
			}
		}
		if !found {
			if f, ok := dev.Fields[fieldID]; ok {
				col := CSVColumn{
					PhysicalPrefix: physicalPrefix,
					FieldID:        fieldID,
					HeaderName:     getCSVHeaderName(physicalPrefix, dev.DeviceName, f),
				}
				s.LogColumns = append(s.LogColumns, col)
			}
		}
	}
}

func (s *DashboardState) startLogging() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.LogActive {
		return
	}

	// 1. Determine filename
	now := time.Now()
	var filename string
	if s.LogFileSetting == "" || s.LogFileSetting == "auto" {
		filename = fmt.Sprintf("log_%s.csv", now.Format("20060102_150405"))
	} else {
		filename = s.LogFileSetting
	}

	// 2. Open temporary raw file
	tempFilename := filename + ".tmp.csv"
	file, err := os.Create(tempFilename)
	if err != nil {
		fmt.Printf("\nError creating log file: %v\n", err)
		return
	}

	s.LogFileName = filename
	s.logFile = file
	s.logWriter = csv.NewWriter(file)
	s.LogActive = true
	s.LogDelayActive = false

	// 3. Populate initial columns based on discovered devices/fields
	s.LogColumns = nil
	var prefixes []uint32
	for prefix := range s.Devices {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i] < prefixes[j] })

	for _, prefix := range prefixes {
		dev := s.Devices[prefix]
		var fieldIDs []byte
		for fid := range dev.Fields {
			fieldIDs = append(fieldIDs, fid)
		}
		sort.Slice(fieldIDs, func(i, j int) bool { return fieldIDs[i] < fieldIDs[j] })

		for _, fid := range fieldIDs {
			field := dev.Fields[fid]
			col := CSVColumn{
				PhysicalPrefix: prefix,
				FieldID:        fid,
				HeaderName:     getCSVHeaderName(prefix, dev.DeviceName, field),
			}
			s.LogColumns = append(s.LogColumns, col)
		}
	}

	// 4. Start Ticker
	s.logDone = make(chan bool)
	s.logTicker = time.NewTicker(s.LogInterval)

	go func(ticker *time.Ticker, done chan bool) {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				s.writeLogLine()
			}
		}
	}(s.logTicker, s.logDone)
}

func (s *DashboardState) stopLogging() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.LogDelayActive {
		s.LogDelayActive = false
		s.LogActive = false
		return
	}

	if !s.LogActive {
		return
	}

	// 1. Stop Ticker
	if s.logTicker != nil {
		s.logTicker.Stop()
	}
	if s.logDone != nil {
		close(s.logDone)
	}

	// 2. Close temporary file
	if s.logWriter != nil {
		s.logWriter.Flush()
	}
	if s.logFile != nil {
		s.logFile.Close()
	}

	s.LogActive = false

	// 3. Finalize CSV: read temp file, prepend header, pad rows, and write to final file
	tempFilename := s.LogFileName + ".tmp.csv"
	finalFilename := s.LogFileName

	tempFile, err := os.Open(tempFilename)
	if err != nil {
		fmt.Printf("\nError opening temp log file for finalization: %v\n", err)
		return
	}
	defer tempFile.Close()

	finalFile, err := os.Create(finalFilename)
	if err != nil {
		fmt.Printf("\nError creating final log file: %v\n", err)
		return
	}
	defer finalFile.Close()

	reader := csv.NewReader(tempFile)
	reader.FieldsPerRecord = -1

	writer := csv.NewWriter(finalFile)

	// 3a. Write Header Row
	header := make([]string, 1, 1+len(s.LogColumns))
	header[0] = "Timestamp"
	for _, col := range s.LogColumns {
		header = append(header, col.HeaderName)
	}
	writer.Write(header)

	// 3b. Read, Pad, and Write all rows
	targetLen := 1 + len(s.LogColumns)
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}

		for len(record) < targetLen {
			record = append(record, "")
		}
		if len(record) > targetLen {
			record = record[:targetLen]
		}

		writer.Write(record)
	}

	writer.Flush()
	tempFile.Close()
	finalFile.Close()

	os.Remove(tempFilename)
}

func (s *DashboardState) writeLogLine() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.LogActive || s.logWriter == nil {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")

	row := make([]string, 1, 1+len(s.LogColumns))
	row[0] = timestamp

	for _, col := range s.LogColumns {
		val := ""
		if dev, ok := s.Devices[col.PhysicalPrefix]; ok {
			if f, ok := dev.Fields[col.FieldID]; ok {
				val = f.Value
			}
		}
		row = append(row, val)
	}

	s.logWriter.Write(row)
	s.logWriter.Flush()
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

	// Print CSV Logging Status
	logStatus := "\033[1;30mINACTIVE\033[0m"
	if state.LogActive {
		logStatus = fmt.Sprintf("\033[1;32mACTIVE\033[0m (file: %s, interval: %v)", state.LogFileName, state.LogInterval)
	} else if state.LogDelayActive {
		timeLeft := time.Until(state.LogDelayEndTime).Seconds()
		if timeLeft < 0 {
			timeLeft = 0
		}
		logStatus = fmt.Sprintf("\033[1;33mWAITING\033[0m (starting in %.1fs, discovering sensors...)", timeLeft)
	}
	fmt.Printf("Logging: %s\033[K\n", logStatus)
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
				case 0x4BA6E2, 0x6FA6E2:
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
	fmt.Println("\nPress Ctrl+C to exit. Type 'stop' (t) / 'start' (s) to control CSV logging.\033[K")
}

func main() {
	portFlag := flag.String("port", "COM17", "Serial port to connect to")
	baudFlag := flag.Int("baud", 250000, "Baud rate")
	logFlag := flag.Bool("log", false, "Enable CSV data logging")
	logIntervalFlag := flag.Duration("log-interval", 1*time.Second, "Interval between log rows")
	logDelayFlag := flag.Duration("log-delay", 30*time.Second, "Startup delay before logging begins")
	logFileFlag := flag.String("log-file", "", "Output CSV filename")
	flag.Parse()

	state := newDashboardState(*portFlag, *baudFlag)
	state.LogEnabled = *logFlag
	state.LogInterval = *logIntervalFlag
	state.LogDelay = *logDelayFlag
	state.LogFileSetting = *logFileFlag

	// Set up serial mode
	mode := &serial.Mode{
		BaudRate: *baudFlag,
		Parity:   serial.NoParity,
		DataBits: 8,
		StopBits: serial.OneStopBit,
	}

	if state.LogEnabled {
		state.LogDelayActive = true
		state.LogDelayEndTime = time.Now().Add(state.LogDelay)
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					state.mu.Lock()
					if state.LogDelayActive && time.Now().After(state.LogDelayEndTime) {
						state.mu.Unlock()
						state.startLogging()
						return
					}
					if !state.LogDelayActive {
						state.mu.Unlock()
						return
					}
					state.mu.Unlock()
				}
			}
		}()
	}

	// Stdin Command reader goroutine
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			text, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			text = strings.TrimSpace(strings.ToLower(text))
			if text == "start" || text == "s" {
				state.startLogging()
			} else if text == "stop" || text == "t" {
				state.stopLogging()
			}
		}
	}()

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
							lenEx := int(pkt.Payload[1])
							textStart := 3 + lenEx
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
	state.stopLogging()
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
	if len(payload) < 4 {
		return
	}
	lenEx := int(payload[1])
	if len(payload) < 3+lenEx {
		return
	}

	// The EX packet starts at payload[3]
	if payload[3]&0x0F != 0x0F {
		return
	}

	// Product ID is 2 bytes (bytes 2-3 of EX packet), Device ID is 4 bytes (bytes 4-7 of EX packet)
	// These correspond to payload[5:9] (which is little-endian uint32 devID)
	if len(payload) < 9 {
		return
	}
	devID := binary.LittleEndian.Uint32(payload[5:9])
	physicalPrefix := devID & 0x00FFFFFF

	exType := (payload[4] >> 6) & 0x03
	exLength := int(payload[4] & 0x3F)

	if exType == 1 {
		idx := 10
		endIdx := 4 + exLength
		for idx < endIdx {
			if idx >= len(payload) {
				break
			}
			firstByte := payload[idx]
			idx++

			fieldID := firstByte >> 4
			dataType := firstByte & 0x0F

			size := getDataTypeSize(dataType)
			if idx+size > endIdx || idx+size > len(payload) {
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
			if precision > 0 {
				valStr = fmt.Sprintf("%.*f", precision, floatVal)
			} else {
				valStr = fmt.Sprintf("%.0f", floatVal)
			}

			state.UpdateValue(physicalPrefix, fieldID, valStr)
		}
	} else if exType == 0 {
		// Text packet: text label definitions start at index 10
		idx := 10
		endIdx := 4 + exLength
		if idx+2 <= endIdx && idx+2 <= len(payload) {
			fieldID := payload[idx]
			idx++
			lengths := payload[idx]
			idx++
			descLen := int(lengths >> 3)
			unitLen := int(lengths & 0x07)

			if idx+descLen+unitLen <= endIdx && idx+descLen+unitLen <= len(payload) {
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
