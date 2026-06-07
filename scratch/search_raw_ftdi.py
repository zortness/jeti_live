import struct
import os

def parse_pcapng(filepath):
    packets = []
    with open(filepath, 'rb') as f:
        shb_header = f.read(8)
        if len(shb_header) < 8:
            return packets
        block_type, block_len = struct.unpack('<II', shb_header)
        if block_type != 0x0A0D0D0A:
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
            f.read(4) # footer
            
            if block_type == 0x00000006:
                interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack('<IIIII', body[:20])
                packet_data = body[20:20+cap_len]
                packets.append(packet_data)
    return packets

def main():
    pcap_files = ['usbcapture1.pcapng']
    for pcap_file in pcap_files:
        if not os.path.exists(pcap_file):
            continue
        packets = parse_pcapng(pcap_file)
        
        print(f"Searching raw packets in {pcap_file}...")
        for i, pkt in enumerate(packets):
            # Let's search the packet for the pattern of SET_BAUD_RATE (0x40 0x03) or SET_DATA (0x40 0x04)
            # which would be vendor control requests
            idx = pkt.find(b'@\x03') # 0x40 0x03
            if idx != -1:
                print(f"Packet #{i:5d}: Found 40 03 at index {idx}")
                # Print around it
                start = max(0, idx - 10)
                end = min(len(pkt), idx + 15)
                print(f"  Context: {pkt[start:end].hex(' ').upper()}")
            
            idx2 = pkt.find(b'@\x04') # 0x40 0x04
            if idx2 != -1:
                print(f"Packet #{i:5d}: Found 40 04 at index {idx2}")
                start = max(0, idx2 - 10)
                end = min(len(pkt), idx2 + 15)
                print(f"  Context: {pkt[start:end].hex(' ').upper()}")

if __name__ == "__main__":
    main()
