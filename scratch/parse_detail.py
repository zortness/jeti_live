import struct
import sys

sys.stdout.reconfigure(encoding='utf-8')

def read_pcap(filename):
    packets = []
    with open(filename, 'rb') as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            return packets
        
        magic = global_header[:4]
        if magic == b'\xa1\xb2\xc3\xd4':
            endian = '>'
        elif magic == b'\xd4\xc3\xb2\xa1':
            endian = '<'
        else:
            return packets
            
        while True:
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', pkt_header)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            packets.append(pkt_data)
    return packets

pkts = read_pcap("live_capture.pcap")
jeti_packets = []
for p in pkts:
    idx = 0
    while True:
        pos = p.find(b'\x3C\x02', idx)
        if pos == -1:
            break
        if pos + 3 < len(p):
            length = p[pos+2]
            if pos + length <= len(p):
                jeti_packets.append(p[pos : pos + length])
        idx = pos + 1

# Let's inspect the first few instances of each unique prefix
by_prefix = {}
for jp in jeti_packets:
    if len(jp) < 8:
        continue
    cmd_type = jp[5]
    payload = jp[6:-2]
    if len(payload) >= 2:
        prefix = (cmd_type, payload[0], payload[1])
        if prefix not in by_prefix:
            by_prefix[prefix] = []
        if len(by_prefix[prefix]) < 3:
            by_prefix[prefix].append(payload)

for prefix, payloads in sorted(by_prefix.items()):
    print("=" * 60)
    print(f"CmdType {prefix[0]:02X}, Payload[0] {prefix[1]:02X}, Payload[1] {prefix[2]:02X}")
    print("=" * 60)
    for p in payloads:
        # Hex dump
        hex_dump = p.hex().upper()
        # Find printable parts
        ascii_parts = []
        temp_str = ""
        for b in p:
            if 32 <= b <= 126 or 160 <= b <= 255:
                temp_str += chr(b)
            else:
                if len(temp_str) >= 2:
                    ascii_parts.append(temp_str)
                temp_str = ""
        if len(temp_str) >= 2:
            ascii_parts.append(temp_str)
            
        print(f"  Hex: {hex_dump}")
        print(f"  ASCII: {repr(ascii_parts)}")
        print("-" * 40)
