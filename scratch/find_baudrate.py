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
            
            if block_type == 0x00000001:
                interface_count += 1
            elif block_type == 0x00000006:
                interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack('<IIIII', body[:20])
                packet_data = body[20:20+cap_len]
                packets.append(packet_data)
    return packets

def decode_ftdi_baudrate(wValue, wIndex):
    # FTDI baudrate encoding:
    # wValue = divisor (14..0), subdivisor (16..15)
    # wIndex = port / high bits of divisor
    # Let's see: FTDI divisor calculation is:
    # Baudrate = 3000000 / (divisor + subdivisor)
    # Subdivisor mapping: 
    # 000 = 0, 001 = 0.5, 010 = 0.25, 011 = 0.125, 100 = 0.375, 101 = 0.625, 110 = 0.75, 111 = 0.875
    # Let's print wValue and wIndex first.
    return wValue, wIndex

def main():
    pcap_files = ['usbcapture1.pcapng', 'usbcapture3.pcapng']
    for pcap_file in pcap_files:
        if not os.path.exists(pcap_file):
            continue
        print(f"\n=================== Baud Rate Config in {pcap_file} ===================")
        packets = parse_pcapng(pcap_file)
        
        for i, pkt in enumerate(packets):
            if len(pkt) < 27:
                continue
            header_len = struct.unpack('<H', pkt[:2])[0]
            transfer_type = pkt[22]
            
            if transfer_type == 2: # URB_CONTROL
                if len(pkt) >= header_len + 8:
                    setup = pkt[header_len:header_len+8]
                    req_type, request, val, idx, length = struct.unpack('<BBHHH', setup)
                    if req_type == 0x40 and request == 0x03: # SET_BAUD_RATE
                        print(f"Packet #{i}: SET_BAUD_RATE: wValue=0x{val:04X}, wIndex=0x{idx:04X}")
                        # Let's decode baudrate
                        # FTDI divisor encoding:
                        # divisor is val & 0x3FFF
                        # subdivisor is encoded in bits 14..16 of val/idx:
                        # subdivisor bits are: bit 14, 15 of val, and bit 0 of idx?
                        # Actually:
                        # subdivisor coding:
                        # 0: .0, 1: .5, 2: .25, 3: .125, 4: .375, 5: .625, 6: .75, 7: .875
                        # Let's check common baudrates:
                        # 9600: divisor = 312.5 (3000000/9600) -> divisor=312, subdivisor=0.5 (code 1) -> wValue = 0x4138 (or similar)
                        # 115200: divisor = 26.0416 (3000000/115200) -> divisor=26, subdivisor=0.0 (code 0) -> wValue = 0x001A
                        # Let's print the actual values.
                        
                        # A quick lookup table for baudrates:
                        # 115200: 0x001A
                        # 9600: 0x4138
                        # 38400: 0x004E
                        # 57600: 0x0034
                        # 230400: 0x000D
                        # 460800: 0x4006
                        # 921600: 0x8003
                        print(f"  wValue={val}, wIndex={idx}")
                        
                        # Decode baud rate formula:
                        # FT_SUB_DIV_CODE = [0, 4, 2, 6, 1, 5, 3, 7]
                        # subdiv = FT_SUB_DIV_CODE[((val >> 14) & 3) | ((idx & 1) << 2)]
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
                        print(f"  Calculated Baud Rate: {baud}")

if __name__ == "__main__":
    main()
