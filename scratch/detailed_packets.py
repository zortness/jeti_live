import struct
import os

def parse_pcapng(filepath):
    packets = []
    link_types = {}
    interface_count = 0
    
    with open(filepath, 'rb') as f:
        shb_header = f.read(8)
        if len(shb_header) < 8:
            return packets
        block_type, block_len = struct.unpack('<II', shb_header)
        if block_type != 0x0A0D0D0A:
            f.seek(0)
            pcap_magic = f.read(4)
            if pcap_magic in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'):
                return parse_pcap(filepath)
            return packets
        
        f.seek(0)
        while True:
            header = f.read(8)
            if len(header) < 8:
                break
            block_type, block_len = struct.unpack('<II', header)
            if block_len < 12:
                break
            
            body_len = block_len - 12
            body = f.read(body_len)
            footer = f.read(4)
            
            if block_type == 0x00000001:
                link_type = struct.unpack('<H', body[:2])[0]
                link_types[interface_count] = link_type
                interface_count += 1
            elif block_type == 0x00000006:
                interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack('<IIIII', body[:20])
                packet_data = body[20:20+cap_len]
                packets.append({
                    'interface_id': interface_id,
                    'link_type': link_types.get(interface_id, 0),
                    'data': packet_data
                })
    return packets

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
            packets.append({
                'interface_id': 0,
                'link_type': network,
                'data': packet_data
            })
    return packets

def extract_ftdi_stream(packets):
    tx_stream = bytearray()
    rx_stream = bytearray()
    
    for pkt in packets:
        pkt_data = pkt['data']
        if len(pkt_data) < 27:
            continue
        header_len = struct.unpack('<H', pkt_data[:2])[0]
        if header_len > len(pkt_data):
            continue
        
        endpoint = pkt_data[21]
        data_len = struct.unpack('<I', pkt_data[23:27])[0]
        
        payload = pkt_data[header_len:header_len+data_len]
        if len(payload) == 0:
            continue
            
        is_in = (endpoint & 0x80) != 0
        
        if is_in:
            if len(payload) >= 2:
                rx_stream.extend(payload[2:])
        else:
            tx_stream.extend(payload)
            
    return tx_stream, rx_stream

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

def parse_and_print_packets(stream, name):
    idx = 0
    packet_count = 0
    
    while idx < len(stream):
        # Scan for start of packet: '>' (0x3E) or '<' (0x3C), followed by 0x02
        pos_tx = stream.find(b'>\x02', idx)
        pos_rx = stream.find(b'<\x02', idx)
        
        if pos_tx == -1 and pos_rx == -1:
            break
            
        if pos_tx == -1:
            pos = pos_rx
            is_tx = False
        elif pos_rx == -1:
            pos = pos_tx
            is_tx = True
        else:
            if pos_tx < pos_rx:
                pos = pos_tx
                is_tx = True
            else:
                pos = pos_rx
                is_tx = False
                
        if pos + 4 > len(stream):
            break
            
        length = stream[pos+2]
        if length < 6: # Minimum packet size (STX:2 + Len:1 + Seq:1 + Cmd:1 + CRC:2 = 7, or similar)
            idx = pos + 1
            continue
            
        if pos + length > len(stream):
            # Incomplete packet in stream
            idx = pos + 1
            continue
            
        packet_bytes = stream[pos:pos+length]
        
        # Verify CRC
        data_to_check = packet_bytes[:-2]
        expected_crc = struct.unpack('<H', packet_bytes[-2:])[0]
        actual_crc = crc16_ref(data_to_check)
        crc_ok = "OK" if expected_crc == actual_crc else f"ERR (exp {expected_crc:04X}, got {actual_crc:04X})"
        
        direction = "TX (Host->Dev)" if is_tx else "RX (Dev->Host)"
        seq = packet_bytes[3]
        byte4 = packet_bytes[4]
        cmd_type = packet_bytes[5]
        payload = packet_bytes[6:-2]
        
        # Human readable payload translation
        payload_desc = ""
        if cmd_type == 0x02: # Bootloader/Identification?
            if b'JETIBOX' in payload:
                payload_desc = f"ID String: '{payload.decode('ascii', errors='ignore').strip()}'"
        
        print(f"[{name}] BytePos {pos:7d} | {direction} | Len: {length:3d} | Seq: {seq:2X} | B4: {byte4:02X} | Cmd: {cmd_type:02X} | CRC: {crc_ok}")
        print(f"  Raw: {packet_bytes.hex(' ').upper()}")
        if payload_desc:
            print(f"  Info: {payload_desc}")
        else:
            print(f"  Payload: {payload.hex(' ').upper()}")
            
        idx = pos + length
        packet_count += 1
        if packet_count >= 250:
            print("... truncated after 250 packets ...")
            break

def main():
    pcap_files = ['usbcapture1.pcapng', 'usbcapture3.pcapng']
    for pcap_file in pcap_files:
        if not os.path.exists(pcap_file):
            continue
        print(f"\n=================== Detailed Packets from {pcap_file} ===================")
        packets = parse_pcapng(pcap_file)
        tx_stream, rx_stream = extract_ftdi_stream(packets)
        
        interleaved_stream = []
        for pkt in packets:
            pkt_data = pkt['data']
            if len(pkt_data) < 27:
                continue
            header_len = struct.unpack('<H', pkt_data[:2])[0]
            endpoint = pkt_data[21]
            data_len = struct.unpack('<I', pkt_data[23:27])[0]
            payload = pkt_data[header_len:header_len+data_len]
            if len(payload) == 0:
                continue
            is_in = (endpoint & 0x80) != 0
            if is_in:
                if len(payload) >= 2:
                    interleaved_stream.append((is_in, payload[2:]))
            else:
                interleaved_stream.append((is_in, payload))
                
        tx_buf = bytearray()
        rx_buf = bytearray()
        all_parsed_packets = []
        
        for is_in, chunk in interleaved_stream:
            if is_in:
                rx_buf.extend(chunk)
                while True:
                    pos = rx_buf.find(b'<\x02')
                    if pos == -1:
                        if len(rx_buf) > 1000:
                            rx_buf = rx_buf[-100:]
                        break
                    if pos + 4 > len(rx_buf):
                        break
                    length = rx_buf[pos+2]
                    if length < 6:
                        rx_buf = rx_buf[pos+1:]
                        continue
                    if pos + length > len(rx_buf):
                        break
                    packet_bytes = rx_buf[pos:pos+length]
                    all_parsed_packets.append((False, packet_bytes))
                    rx_buf = rx_buf[pos+length:]
            else:
                tx_buf.extend(chunk)
                while True:
                    pos = tx_buf.find(b'>\x02')
                    if pos == -1:
                        if len(tx_buf) > 1000:
                            tx_buf = tx_buf[-100:]
                        break
                    if pos + 4 > len(tx_buf):
                        break
                    length = tx_buf[pos+2]
                    if length < 6:
                        tx_buf = tx_buf[pos+1:]
                        continue
                    if pos + length > len(tx_buf):
                        break
                    packet_bytes = tx_buf[pos:pos+length]
                    all_parsed_packets.append((True, packet_bytes))
                    tx_buf = tx_buf[pos+length:]
                    
        # Print first 60 packets
        print(f"Total parsed packets: {len(all_parsed_packets)}")
        for i, (is_tx, pkt) in enumerate(all_parsed_packets[:60]):
            direction = "TX (Host->Dev)" if is_tx else "RX (Dev->Host)"
            length = pkt[2]
            seq = pkt[3]
            byte4 = pkt[4]
            cmd_type = pkt[5]
            payload = pkt[6:-2]
            
            expected_crc = struct.unpack('<H', pkt[-2:])[0]
            actual_crc = crc16_ref(pkt[:-2])
            crc_ok = "OK" if expected_crc == actual_crc else f"ERR (exp {expected_crc:04X}, got {actual_crc:04X})"
            
            payload_desc = ""
            if cmd_type == 0x02:
                if b'JETIBOX' in payload:
                    payload_desc = f"ID String: '{payload.decode('ascii', errors='ignore').strip()}'"
            elif cmd_type == 0x30:
                printable = "".join([chr(c) if 32 <= c <= 126 or 160 <= c <= 255 else '.' for c in payload])
                payload_desc = f"Text: '{printable}'"
            
            print(f"#{i:02d} | {direction} | Len: {length:3d} | Seq: {seq:02X} | B4: {byte4:02X} | Cmd: {cmd_type:02X} | CRC: {crc_ok}")
            print(f"  Raw: {pkt.hex(' ').upper()}")
            if payload_desc:
                print(f"  Info: {payload_desc}")
            else:
                print(f"  Payload: {payload.hex(' ').upper()}")

if __name__ == "__main__":
    main()
