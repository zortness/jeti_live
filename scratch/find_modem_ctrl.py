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
    pcap_files = ['usbcapture1.pcapng', 'usbcapture3.pcapng']
    for pcap_file in pcap_files:
        if not os.path.exists(pcap_file):
            continue
        print(f"\n=================== FTDI Modem / Flow Control in {pcap_file} ===================")
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
                    
                    # FTDI Requests:
                    # 1: SET_MODEM_CTRL
                    # 2: SET_FLOW_CTRL
                    if req_type == 0x40 and request in (1, 2):
                        req_name = "SET_MODEM_CTRL" if request == 1 else "SET_FLOW_CTRL"
                        print(f"Packet #{i:5d} | {req_name}: wValue=0x{val:04X}, wIndex=0x{idx:04X}")
                        if request == 1:
                            # Decode DTR / RTS
                            # High byte has mask (bit 8: DTR, bit 9: RTS)
                            # Low byte has values (bit 0: DTR, bit 1: RTS)
                            dtr_mask = (val & 0x0100) != 0
                            rts_mask = (val & 0x0200) != 0
                            dtr_val = (val & 0x0001) != 0
                            rts_val = (val & 0x0002) != 0
                            
                            desc = []
                            if dtr_mask:
                                desc.append(f"DTR={dtr_val}")
                            if rts_mask:
                                desc.append(f"RTS={rts_val}")
                            print(f"  Modem Ctrl Action: {', '.join(desc)}")
                        elif request == 2:
                            # Flow control: high byte / low byte
                            # wValue = XON/XOFF character
                            # wIndex = Flow control protocol
                            # wIndex high byte has flow control type:
                            # 0: NONE, 0x01: RTS/CTS, 0x02: DTR/DSR, 0x04: XON/XOFF
                            flow_type = (idx >> 8) & 0xFF
                            flow_names = {0: "NONE", 1: "RTS/CTS", 2: "DTR/DSR", 4: "XON/XOFF"}
                            print(f"  Flow Control: {flow_names.get(flow_type, 'UNKNOWN')} (0x{flow_type:02X})")

if __name__ == "__main__":
    main()
