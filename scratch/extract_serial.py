import struct
import os

def parse_pcapng(filepath):
    packets = []
    link_types = {}
    interface_count = 0
    
    with open(filepath, 'rb') as f:
        # Read Section Header Block (must start with 0x0A0D0D0A)
        shb_header = f.read(8)
        if len(shb_header) < 8:
            return packets
        block_type, block_len = struct.unpack('<II', shb_header)
        if block_type != 0x0A0D0D0A:
            # Maybe it is a standard PCAP file?
            # Let's check magic
            f.seek(0)
            pcap_magic = f.read(4)
            if pcap_magic in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'):
                print("Detected standard PCAP format")
                return parse_pcap(filepath)
            print(f"Unknown magic: {block_type:08X}")
            return packets
        
        # Seek back to start
        f.seek(0)
        
        while True:
            header = f.read(8)
            if len(header) < 8:
                break
            block_type, block_len = struct.unpack('<II', header)
            if block_len < 12:
                print(f"Invalid block length {block_len}")
                break
            
            body_len = block_len - 12
            body = f.read(body_len)
            footer = f.read(4)
            
            if block_type == 0x00000001: # Interface Description Block
                link_type = struct.unpack('<H', body[:2])[0]
                link_types[interface_count] = link_type
                interface_count += 1
            elif block_type == 0x00000006: # Enhanced Packet Block
                interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack('<IIIII', body[:20])
                packet_data = body[20:20+cap_len]
                packets.append({
                    'interface_id': interface_id,
                    'link_type': link_types.get(interface_id, 0),
                    'data': packet_data
                })
    return packets

def parse_pcap(filepath):
    # Minimal standard PCAP parser
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
    
    # We need to parse USBPcap pseudoheader (usually 27 or 28 bytes)
    # The header starts with 2 bytes header length.
    for pkt in packets:
        pkt_data = pkt['data']
        if len(pkt_data) < 27:
            continue
        header_len = struct.unpack('<H', pkt_data[:2])[0]
        if header_len > len(pkt_data):
            continue
        
        # USBPcap header fields:
        # 0..1: headerLen
        # 2..9: irpId
        # 10..13: status
        # 14..15: function
        # 16: info (PDO->FDO is bit 0, which is device-to-host IN)
        # 17..18: bus
        # 19..20: device
        # 21: endpoint (bit 7 is direction: 1=IN, 0=OUT)
        # 22: transfer_type (3=BULK)
        # 23..26: data_len
        info = pkt_data[16]
        endpoint = pkt_data[21]
        transfer_type = pkt_data[22]
        data_len = struct.unpack('<I', pkt_data[23:27])[0]
        
        payload = pkt_data[header_len:header_len+data_len]
        if len(payload) == 0:
            continue
            
        is_in = (endpoint & 0x80) != 0
        
        if is_in:
            # Device to Host (RX from host perspective)
            # FTDI status bytes are first 2 bytes
            if len(payload) >= 2:
                status_bytes = payload[:2]
                actual_data = payload[2:]
                rx_stream.extend(actual_data)
        else:
            # Host to Device (TX from host perspective)
            tx_stream.extend(payload)
            
    return tx_stream, rx_stream

def find_packets(stream, is_tx):
    # Packets start with '>' (0x3E) for TX, '<' (0x3C) for RX.
    # Followed by 0x02.
    # Followed by 2 bytes length (little-endian).
    # Then payload.
    # Let's search the stream for these frames.
    prefix = b'>\x02' if is_tx else b'<\x02'
    idx = 0
    packets = []
    while idx < len(stream):
        pos = stream.find(prefix, idx)
        if pos == -1:
            break
        if pos + 4 > len(stream):
            idx = pos + 1
            continue
        length = struct.unpack('<H', stream[pos+2:pos+4])[0]
        if length < 4:
            # Avoid infinite loop if length is less than header size
            idx = pos + 4
            continue
        if pos + length > len(stream):
            # Incomplete packet, skip or stop
            idx = pos + 1
            continue
        packet_bytes = stream[pos:pos+length]
        packets.append((pos, packet_bytes))
        idx = pos + length
    return packets

def main():
    pcap_files = ['usbcapture1.pcapng', 'usbcapture2.pcapng', 'usbcapture3.pcapng']
    for pcap_file in pcap_files:
        if not os.path.exists(pcap_file):
            print(f"Skipping missing file: {pcap_file}")
            continue
        print(f"\n=================== Analyzing {pcap_file} ===================")
        packets = parse_pcapng(pcap_file)
        print(f"Parsed {len(packets)} USB packets.")
        
        tx_stream, rx_stream = extract_ftdi_stream(packets)
        print(f"Extracted TX stream: {len(tx_stream)} bytes, RX stream: {len(rx_stream)} bytes.")
        
        tx_packets = find_packets(tx_stream, is_tx=True)
        rx_packets = find_packets(rx_stream, is_tx=False)
        print(f"Found {len(tx_packets)} TX packets, {len(rx_packets)} RX packets.")
        
        print("\nFirst 10 TX Packets:")
        for pos, pkt in tx_packets[:10]:
            print(f"  Pos {pos:5d}: {pkt.hex(' ').upper()}")
            
        print("\nFirst 10 RX Packets:")
        for pos, pkt in rx_packets[:10]:
            print(f"  Pos {pos:5d}: {pkt.hex(' ').upper()}")

if __name__ == "__main__":
    main()
