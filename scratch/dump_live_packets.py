import struct
import os

def parse_pcap(filepath):
    packets = []
    with open(filepath, 'rb') as f:
        header = f.read(24)
        if len(header) < 24:
            return packets
        magic, version_maj, version_min, thiszone, sigfigs, snaplen, network = struct.unpack('<IHHIIII', header)
        swap = False
        if magic == 0xd4c3b2a1:
            swap = True
            
        while True:
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII' if not swap else '>IIII', rec_hdr)
            packet_data = f.read(incl_len)
            packets.append(packet_data)
    return packets

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

def parse_packets_from_stream(stream, is_tx):
    prefix = b'>\x02' if is_tx else b'<\x02'
    idx = 0
    parsed = []
    while idx < len(stream):
        pos = stream.find(prefix, idx)
        if pos == -1:
            break
        if pos + 4 > len(stream):
            idx = pos + 1
            continue
        length = stream[pos+2]
        if length < 6:
            idx = pos + 1
            continue
        if pos + length > len(stream):
            idx = pos + 1
            continue
        packet_bytes = stream[pos:pos+length]
        parsed.append(packet_bytes)
        idx = pos + length
    return parsed

def main():
    filepath = "live_capture.pcap"
    if not os.path.exists(filepath):
        print("File not found.")
        return
    packets = parse_pcap(filepath)
    print(f"Parsed {len(packets)} packets from {filepath}")
    
    current_baud = 115200 # initial default
    
    # We buffer streams for each baud rate
    streams = {}
    
    for pkt in packets:
        if len(pkt) < 28:
            continue
        header_len = struct.unpack('<H', pkt[:2])[0]
        transfer_type = pkt[22]
        endpoint = pkt[21]
        data_len = struct.unpack('<I', pkt[23:27])[0]
        
        if transfer_type == 2: # URB_CONTROL
            if len(pkt) >= header_len + 8:
                setup = pkt[header_len:header_len+8]
                req_type, request, val, idx, length = struct.unpack('<BBHHH', setup)
                if req_type == 0x40 and request == 3: # SET_BAUD_RATE
                    subdiv_code = ((val >> 14) & 3) | ((idx & 1) << 2)
                    subdiv_map = {0: 0.0, 1: 0.5, 2: 0.25, 3: 0.125, 4: 0.375, 5: 0.625, 6: 0.75, 7: 0.875}
                    subdiv = subdiv_map.get(subdiv_code, 0.0)
                    divisor = val & 0x3FFF
                    if divisor == 0 and subdiv == 0:
                        baud = 3000000
                    elif divisor == 1 and subdiv == 0:
                        baud = 2000000
                    else:
                        baud = int(3000000 / (divisor + subdiv))
                    current_baud = baud
                    
        elif transfer_type == 3: # URB_BULK
            is_in = (endpoint & 0x80) != 0
            payload = pkt[header_len:header_len+data_len]
            if len(payload) > 0:
                if current_baud not in streams:
                    streams[current_baud] = {'tx': bytearray(), 'rx': bytearray()}
                if is_in:
                    if len(payload) >= 2:
                        streams[current_baud]['rx'].extend(payload[2:])
                else:
                    streams[current_baud]['tx'].extend(payload)
                    
    # Now parse and print packets for each baud rate
    for baud, data in streams.items():
        print(f"\n=================== PACKETS AT {baud} BAUD ===================")
        tx_packets = parse_packets_from_stream(data['tx'], is_tx=True)
        rx_packets = parse_packets_from_stream(data['rx'], is_tx=False)
        print(f"Found {len(tx_packets)} TX packets, {len(rx_packets)} RX packets.")
        
        print("\nTX Packets:")
        for i, pkt in enumerate(tx_packets[:10]):
            length = pkt[2]
            seq = pkt[3]
            sub_id = pkt[4]
            cmd_type = pkt[5]
            payload = pkt[6:-2]
            print(f"  #{i:02d} | Len: {length:3d} | Seq: {seq:02X} | Sub-ID: {sub_id:02X} | Cmd: {cmd_type:02X} | Pay: {payload.hex(' ').upper()}")
            
        print("\nRX Packets:")
        for i, pkt in enumerate(rx_packets[:10]):
            length = pkt[2]
            seq = pkt[3]
            sub_id = pkt[4]
            cmd_type = pkt[5]
            payload = pkt[6:-2]
            
            payload_desc = ""
            if cmd_type == 0x02:
                payload_desc = f"ID String: '{payload.decode('ascii', errors='ignore').strip()}'"
            elif cmd_type == 0x30:
                printable = "".join([chr(c) if 32 <= c <= 126 or 160 <= c <= 255 else '.' for c in payload])
                payload_desc = f"Text: '{printable}'"
                
            print(f"  #{i:02d} | Len: {length:3d} | Seq: {seq:02X} | Sub-ID: {sub_id:02X} | Cmd: {cmd_type:02X} | Info: {payload_desc}")
            if not payload_desc:
                print(f"       Raw Payload: {payload.hex(' ').upper()}")

if __name__ == "__main__":
    main()
