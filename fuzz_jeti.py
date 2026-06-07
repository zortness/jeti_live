import serial
import time
import struct
import sys

# Configuration
PORT = 'COM17'
BAUD_RATE = 250000
TIMEOUT = 1.0

def crc16_ref(data: bytes) -> int:
    """Calculates Jeti standard Reflected CRC-16 (poly=0x8408, init=0x0000)."""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc = crc >> 1
    return crc

def make_packet(sub_id: int, cmd_type: int, payload: bytes = b'') -> bytes:
    """Builds a host-to-device Jeti packet with the correct STX header and CRC."""
    header = bytes([0x3E, 0x02]) # STX for Host -> Device ('> \x02')
    # Total packet length = STX(2) + Len(1) + Seq(1) + Sub-ID(1) + CmdType(1) + len(payload) + CRC(2)
    length = 2 + 1 + 1 + 1 + 1 + len(payload) + 2
    
    # Pack header and payload: Seq is 0x00 for host packets
    packet_data = header + bytes([length, 0x00, sub_id, cmd_type]) + payload
    
    # Calculate CRC-16
    crc = crc16_ref(packet_data)
    
    # Append CRC in little-endian format
    packet_data += bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    return packet_data

def parse_device_packets(rx_buffer: bytearray):
    """Searches the buffer for all complete device response packets.
    Returns a list of parsed packets and the remaining unparsed buffer.
    """
    parsed_packets = []
    while True:
        pos = rx_buffer.find(b'\x3C\x02') # STX for Device -> Host ('< \x02')
        if pos == -1:
            if len(rx_buffer) > 1000:
                # Drop old data to prevent buffer bloat
                rx_buffer = rx_buffer[-100:]
            break
            
        if pos + 4 > len(rx_buffer):
            # Keep buffer starting from pos
            rx_buffer = rx_buffer[pos:]
            break
            
        length = rx_buffer[pos+2]
        if length < 6:
            # Invalid length field, discard STX and search again
            rx_buffer = rx_buffer[pos+1:]
            continue
            
        if pos + length > len(rx_buffer):
            # Incomplete packet, wait for more data
            rx_buffer = rx_buffer[pos:]
            break
            
        packet_bytes = rx_buffer[pos:pos+length]
        rx_buffer = rx_buffer[pos+length:]
        
        # Verify CRC
        data_to_check = packet_bytes[:-2]
        expected_crc = struct.unpack('<H', packet_bytes[-2:])[0]
        actual_crc = crc16_ref(data_to_check)
        
        if expected_crc != actual_crc:
            print(f"[CRC Warning] Expected {expected_crc:04X}, got {actual_crc:04X} on packet: {packet_bytes.hex().upper()}")
            continue
            
        # Extract fields
        seq = packet_bytes[3]
        sub_id = packet_bytes[4]
        cmd_type = packet_bytes[5]
        payload = packet_bytes[6:-2]
        
        parsed_packets.append({
            'seq': seq,
            'sub_id': sub_id,
            'cmd_type': cmd_type,
            'payload': payload,
            'raw': packet_bytes
        })
        
    return parsed_packets, rx_buffer

def decode_payload(cmd_type: int, payload: bytes):
    """Decodes JetiBox Profi payload parameters and telemetry display text."""
    if cmd_type == 0x02:
        # Identification query response
        try:
            return f"Device Name/ID: '{payload.decode('ascii', errors='ignore').strip()}'"
        except Exception:
            return f"Raw ID Payload: {payload.hex(' ').upper()}"
            
    elif cmd_type == 0x30:
        # Telemetry Display Packet
        # Extract ASCII strings of 3 or more printable characters
        printable_parts = []
        temp_str = ""
        for b in payload:
            if 32 <= b <= 126 or 160 <= b <= 255:
                temp_str += chr(b)
            else:
                if len(temp_str) >= 3:
                    printable_parts.append(temp_str.strip())
                temp_str = ""
        if len(temp_str) >= 3:
            printable_parts.append(temp_str.strip())
            
        desc = ""
        if printable_parts:
            desc += f"Display Text: {', '.join([f'\"{p}\"' for p in printable_parts])} | "
        
        # Also print raw hex payload
        desc += f"Raw Hex: {payload.hex(' ').upper()}"
        return desc
    
    return f"Raw Payload: {payload.hex(' ').upper()}"

def main():
    print(f"==================================================")
    print(f"JetiBox Profi Interactive Client")
    print(f"==================================================")
    print(f"Connecting to {PORT} at {BAUD_RATE} baud...")
    
    try:
        ser = serial.Serial(PORT, BAUD_RATE, timeout=TIMEOUT)
        # Match Jeti Studio's exact flow control configurations
        ser.dtr = True
        ser.rts = False
        time.sleep(0.1) # Wait for serial lines to settle
    except serial.SerialException as e:
        print(f"Error: Could not open serial port {PORT}: {e}")
        sys.exit(1)
        
    print(f"Connected to {PORT} successfully! Initializing handshake...\n")
    
    rx_buffer = bytearray()
    
    # Clear any junk or pre-existing streaming data from buffer
    ser.reset_input_buffer()
    
    # 1. Host Send Ping / Query ID (using Sub-ID = 0x0E as observed in Jeti Studio)
    ping_pkt = make_packet(sub_id=0x0E, cmd_type=0x02)
    print(f"[TX] Ping Query ID -> {ping_pkt.hex(' ').upper()}")
    ser.write(ping_pkt)
    
    # Read response
    handshake_success = False
    start_time = time.time()
    while time.time() - start_time < 3.0:
        data = ser.read(100)
        if data:
            rx_buffer.extend(data)
            pkts, rx_buffer = parse_device_packets(rx_buffer)
            for pkt in pkts:
                print(f"[RX] Packet Received <- {pkt['raw'].hex(' ').upper()}")
                info = decode_payload(pkt['cmd_type'], pkt['payload'])
                print(f"     Decoded: {info}")
                if pkt['cmd_type'] == 0x02:
                    handshake_success = True
        time.sleep(0.05)
        
    if not handshake_success:
        print("\n[Warning] Handshake ID response not received. Continuing to poll anyway...")
    else:
        print("\nHandshake successful! Sending Telemetry Parameter Registration...")
        # 2. Host Send Parameter Registration (Sub-ID = 0x0F, Cmd = 0x16)
        # Registers parameter fields: 41 ('A'), 42 ('B'), 45 ('E'), 47 ('G')
        reg_payload = bytes.fromhex("41010001420100014501000147010001")
        reg_pkt = make_packet(sub_id=0x0F, cmd_type=0x16, payload=reg_payload)
        print(f"[TX] Reg Parameters -> {reg_pkt.hex(' ').upper()}")
        ser.write(reg_pkt)
        time.sleep(0.2)
        
    print("\nStarting periodic telemetry poll loop. Press Ctrl+C to exit.\n")
    
    # Sequence counter (increments 1 to 15)
    seq = 7
    
    try:
        while True:
            # Increment sequence number (modulo-15 counter wrapping 1..15)
            seq = (seq % 15) + 1
            
            # Send Ping query with current sequence number
            poll_pkt = make_packet(sub_id=seq, cmd_type=0x02)
            print(f"[TX] Poll (Seq {seq:02d}) -> {poll_pkt.hex(' ').upper()}")
            ser.write(poll_pkt)
            
            # Read response (up to 1.0 second timeout)
            poll_start = time.time()
            rx_buffer.clear()
            response_received = False
            
            while time.time() - poll_start < 1.0:
                data = ser.read(100)
                if data:
                    rx_buffer.extend(data)
                    pkts, rx_buffer = parse_device_packets(rx_buffer)
                    for pkt in pkts:
                        response_received = True
                        print(f"[RX] Packet Received <- {pkt['raw'].hex(' ').upper()}")
                        info = decode_payload(pkt['cmd_type'], pkt['payload'])
                        print(f"     Decoded: {info}")
                time.sleep(0.05)
                
            if not response_received:
                print("[RX] No Response (Timeout)")
                
            print("-" * 50)
            time.sleep(2.0) # Poll every 2 seconds
            
    except KeyboardInterrupt:
        print("\nExiting JetiBox client loop.")
    finally:
        ser.close()
        print("Serial port closed.")

if __name__ == "__main__":
    main()
