import struct

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
            print("Not a standard pcap file or different magic:", magic.hex())
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
print(f"Read {len(pkts)} packets from pcap")

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

print(f"Found {len(jeti_packets)} JetiBox packets")

prefixes = {}
for jp in jeti_packets:
    if len(jp) < 8:
        continue
    cmd_type = jp[5]
    payload = jp[6:-2]
    if len(payload) >= 2:
        prefix = (cmd_type, payload[0], payload[1])
        prefixes[prefix] = prefixes.get(prefix, 0) + 1

print("\nPayload Prefix Analysis (CmdType, Payload[0], Payload[1]) -> Count:")
for k, v in sorted(prefixes.items(), key=lambda x: x[1], reverse=True)[:20]:
    print(f"CmdType {k[0]:02X}, Payload[0] {k[1]:02X}, Payload[1] {k[2]:02X} -> count: {v}")
