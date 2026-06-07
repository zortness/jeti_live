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
                # Timestamp in microseconds (usually USBPcap uses 1 microsecond resolution)
                ts = (ts_high << 32) | ts_low
                packets.append((ts, packet_data))
    return packets

def main():
    pcap_file = 'usbcapture1.pcapng'
    if not os.path.exists(pcap_file):
        return
    packets = parse_pcapng(pcap_file)
    
    interleaved = []
    for ts, pkt_data in packets:
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
                interleaved.append((ts, is_in, payload[2:]))
        else:
            interleaved.append((ts, is_in, payload))
            
    tx_buf = bytearray()
    rx_buf = bytearray()
    parsed_packets = []
    
    for ts, is_in, chunk in interleaved:
        if is_in:
            rx_buf.extend(chunk)
            while True:
                pos = rx_buf.find(b'<\x02')
                if pos == -1:
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
                parsed_packets.append((ts, False, packet_bytes))
                rx_buf = rx_buf[pos+length:]
        else:
            tx_buf.extend(chunk)
            while True:
                pos = tx_buf.find(b'>\x02')
                if pos == -1:
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
                parsed_packets.append((ts, True, packet_bytes))
                tx_buf = tx_buf[pos+length:]
                
    # Now let's print the packets and compute the time difference between consecutive ones
    prev_ts = None
    for i, (ts, is_tx, pkt) in enumerate(parsed_packets[:20]):
        direction = "TX (Host->Dev)" if is_tx else "RX (Dev->Host)"
        length = pkt[2]
        cmd_type = pkt[5]
        
        if prev_ts is not None:
            # USBPcap timestamps are usually in microseconds or 100-nanoseconds
            # Let's see: if diff is around 10000, it's 10ms.
            diff_ms = (ts - prev_ts) / 1000.0  # Assumes microsecond resolution
            print(f"Delay: {diff_ms:8.3f} ms")
            
        print(f"#{i:02d} | {direction} | Len: {length:3d} | Cmd: {cmd_type:02X} | TS: {ts}")
        print(f"  Raw: {pkt.hex(' ').upper()}")
        prev_ts = ts

if __name__ == "__main__":
    main()
