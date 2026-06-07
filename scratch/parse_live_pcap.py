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
        elif magic == 0xa1b2c3d4:
            swap = False
        else:
            print(f"Unknown magic: {magic:08X}")
            return packets
            
        while True:
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII' if not swap else '>IIII', rec_hdr)
            packet_data = f.read(incl_len)
            packets.append(packet_data)
    return packets

def main():
    filepath = "live_capture.pcap"
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return
        
    print(f"Parsing standard PCAP: {filepath}")
    packets = parse_pcap(filepath)
    print(f"Parsed {len(packets)} packets.")
    
    found_any = False
    for i, pkt in enumerate(packets):
        if len(pkt) < 27:
            continue
        header_len = struct.unpack('<H', pkt[:2])[0]
        # In standard PCAP, let's check the offset of transfer type.
        # Wait, USBPcap header is 27 or 28 bytes.
        # Let's extract transfer type.
        # In USBPcap pseudoheader:
        # byte 22 is transfer_type
        if header_len > len(pkt):
            continue
        transfer_type = pkt[22]
        
        if transfer_type == 2: # URB_CONTROL
            if len(pkt) >= header_len + 8:
                setup = pkt[header_len:header_len+8]
                req_type, request, val, idx, length = struct.unpack('<BBHHH', setup)
                
                # FTDI requests:
                # 1: SET_MODEM_CTRL
                # 2: SET_FLOW_CTRL
                # 3: SET_BAUD_RATE
                # 4: SET_DATA
                if req_type == 0x40:
                    found_any = True
                    if request == 3: # SET_BAUD_RATE
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
                        print(f"Packet #{i:5d} | SET_BAUD_RATE: {baud} baud (wValue=0x{val:04X}, wIndex=0x{idx:04X})")
                    elif request == 4: # SET_DATA
                        num_bits = val & 0xFF
                        parity_code = (val >> 8) & 0xF
                        stop_code = (val >> 12) & 0xF
                        parity_map = {0: "NONE", 1: "ODD", 2: "EVEN", 3: "MARK", 4: "SPACE"}
                        stop_map = {0: "1 stop bit", 1: "1.5 stop bits", 2: "2 stop bits"}
                        print(f"Packet #{i:5d} | SET_DATA: {num_bits} bits, Parity: {parity_map.get(parity_code, 'UNKNOWN')}, Stop: {stop_map.get(stop_code, 'UNKNOWN')}")
                    elif request == 2: # SET_FLOW_CTRL
                        flow_type = (idx >> 8) & 0xFF
                        flow_names = {0: "NONE", 1: "RTS/CTS", 2: "DTR/DSR", 4: "XON/XOFF"}
                        print(f"Packet #{i:5d} | SET_FLOW_CTRL: {flow_names.get(flow_type, 'UNKNOWN')}")
                    elif request == 1: # SET_MODEM_CTRL
                        dtr_val = (val & 0x0001) != 0
                        rts_val = (val & 0x0002) != 0
                        dtr_mask = (val & 0x0100) != 0
                        rts_mask = (val & 0x0200) != 0
                        desc = []
                        if dtr_mask:
                            desc.append(f"DTR={dtr_val}")
                        if rts_mask:
                            desc.append(f"RTS={rts_val}")
                        print(f"Packet #{i:5d} | SET_MODEM_CTRL: {', '.join(desc)} (wValue=0x{val:04X})")
                        
    if not found_any:
        print("No FTDI control requests found in the capture file.")

if __name__ == "__main__":
    main()
