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
        
        for i, pkt in enumerate(packets):
            if len(pkt) < 28:
                continue
            header_len = struct.unpack('<H', pkt[:2])[0]
            transfer_type = pkt[22]
            
            if transfer_type == 2: # URB_CONTROL
                if len(pkt) >= header_len + 8:
                    setup = pkt[header_len:header_len+8]
                    req_type, request, val, idx, length = struct.unpack('<BBHHH', setup)
                    # Print anything that might be FTDI SET_BAUD_RATE or SET_DATA
                    # FTDI requests: 
                    # 0: RESET
                    # 1: SET_MODEM_CTRL
                    # 2: SET_FLOW_CTRL
                    # 3: SET_BAUD_RATE
                    # 4: SET_DATA
                    if request in (0, 1, 2, 3, 4):
                        print(f"Request: {request}, wValue: 0x{val:04X}, wIndex: 0x{idx:04X}")

if __name__ == "__main__":
    main()
