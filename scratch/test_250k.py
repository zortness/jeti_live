import serial
import time
import struct
import sys

PORT = 'COM17'
BAUD = 250000
TIMEOUT = 1.0

def crc16_ref(data: bytes) -> int:
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
    header = bytes([0x3E, 0x02])
    length = 2 + 1 + 1 + 1 + 1 + len(payload) + 2
    packet_data = header + bytes([length, 0x00, sub_id, cmd_type]) + payload
    crc = crc16_ref(packet_data)
    packet_data += bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    return packet_data

def main():
    print(f"Connecting to {PORT} at {BAUD} baud...")
    try:
        ser = serial.Serial(PORT, BAUD, timeout=TIMEOUT)
        # Match Jeti Studio's exact modem line states
        ser.dtr = True
        ser.rts = False
        time.sleep(0.1)
    except Exception as e:
        print(f"Connection failed: {e}")
        return
        
    print("Sending Ping Query ID...")
    # Let's send the Ping query with Sub-ID 0x0E (seq 14) which Jeti Studio used
    ping = make_packet(0x0E, 0x02)
    print(f"  TX: {ping.hex(' ').upper()}")
    ser.write(ping)
    
    # Read response
    rx_buf = bytearray()
    start = time.time()
    while time.time() - start < 2.0:
        data = ser.read(100)
        if data:
            rx_buf.extend(data)
            print(f"  Received chunk: {data.hex(' ').upper()}")
            # Check for complete packet
            pos = rx_buf.find(b'\x3C\x02')
            if pos != -1 and len(rx_buf) >= pos + 4:
                length = rx_buf[pos+2]
                if len(rx_buf) >= pos + length:
                    pkt = rx_buf[pos:pos+length]
                    expected_crc = struct.unpack('<H', pkt[-2:])[0]
                    actual_crc = crc16_ref(pkt[:-2])
                    print(f"  Found packet! CRC: {'OK' if expected_crc == actual_crc else 'ERR'}")
                    print(f"  Packet bytes: {pkt.hex(' ').upper()}")
                    payload = pkt[6:-2]
                    try:
                        print(f"  Device Name: '{payload.decode('ascii', errors='ignore').strip()}'")
                    except:
                        pass
                    break
        time.sleep(0.1)
        
    ser.close()

if __name__ == "__main__":
    main()
