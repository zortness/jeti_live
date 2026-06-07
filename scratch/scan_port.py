import serial
import time
import struct
import sys

PORT = 'COM17'
TIMEOUT = 0.5

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

def test_combination(baud, parity, dtr, rts):
    try:
        # We explicitly set dtr and rts initial states
        ser = serial.Serial(PORT, baud, parity=parity, timeout=TIMEOUT)
        ser.dtr = dtr
        ser.rts = rts
        time.sleep(0.1) # Wait for lines to settle
        
        # Flush buffers
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        
        # Send Ping
        ping = make_packet(0x07, 0x02)
        ser.write(ping)
        
        # Read response
        rx_buf = bytearray()
        start = time.time()
        while time.time() - start < 0.6:
            data = ser.read(50)
            if data:
                rx_buf.extend(data)
                # Look for STX
                pos = rx_buf.find(b'\x3C\x02')
                if pos != -1 and len(rx_buf) >= pos + 4:
                    length = rx_buf[pos+2]
                    if length >= 6 and len(rx_buf) >= pos + length:
                        # We have a candidate packet!
                        pkt_bytes = rx_buf[pos:pos+length]
                        # Verify CRC
                        if crc16_ref(pkt_bytes[:-2]) == struct.unpack('<H', pkt_bytes[-2:])[0]:
                            ser.close()
                            return True, pkt_bytes
            time.sleep(0.05)
            
        ser.close()
        return False, rx_buf
    except Exception as e:
        return False, str(e)

def main():
    print(f"Scanning {PORT} for JetiBox Profi response...")
    
    baud_rates = [9600, 19200, 38400, 57600, 115200]
    parities = [serial.PARITY_NONE, serial.PARITY_ODD, serial.PARITY_EVEN]
    dtr_states = [True, False]
    rts_states = [True, False]
    
    for baud in baud_rates:
        for parity in parities:
            parity_char = {serial.PARITY_NONE: 'N', serial.PARITY_ODD: 'O', serial.PARITY_EVEN: 'E'}[parity]
            for dtr in dtr_states:
                for rts in rts_states:
                    print(f"Testing Baud: {baud:6d} {parity_char}81 | DTR: {int(dtr)} | RTS: {int(rts)} ... ", end='', flush=True)
                    success, res = test_combination(baud, parity, dtr, rts)
                    if success:
                        print("SUCCESS!")
                        print(f"  Received packet: {res.hex(' ').upper()}")
                        print(f"  Configuration found: Baud={baud}, Parity={parity_char}, DTR={dtr}, RTS={rts}")
                        return
                    else:
                        if isinstance(res, bytearray) and len(res) > 0:
                            print(f"No valid packet (got raw: {res.hex(' ').upper()})")
                        elif isinstance(res, str):
                            print(f"Error: {res}")
                        else:
                            print("Timeout")

if __name__ == "__main__":
    main()
