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
        
    packets = parse_pcap(filepath)
    
    current_baud = "UNKNOWN"
    current_parity = "UNKNOWN"
    
    # We want to print FTDI setups and count bulk transfers between setups
    bulk_rx_count = 0
    bulk_tx_count = 0
    bulk_rx_bytes = 0
    bulk_tx_bytes = 0
    
    for i, pkt in enumerate(packets):
        if len(pkt) < 28:
            continue
        header_len = struct.unpack('<H', pkt[:2])[0]
        transfer_type = pkt[22]
        endpoint = pkt[21]
        data_len = struct.unpack('<I', pkt[23:27])[0]
        
        if transfer_type == 2: # URB_CONTROL
            if len(pkt) >= header_len + 8:
                setup = pkt[header_len:header_len+8]
                req_type, request, val, idx, length = struct.unpack('<BBHHH', setup)
                
                if req_type == 0x40 and request in (1, 2, 3, 4):
                    # We print the accumulated bulk stats before changing config
                    if bulk_tx_count > 0 or bulk_rx_count > 0:
                        print(f"  --> Active Config: Baud={current_baud}, Parity={current_parity}")
                        print(f"      Bulk Data: TX={bulk_tx_count} pkts ({bulk_tx_bytes} bytes), RX={bulk_rx_count} pkts ({bulk_rx_bytes} bytes)")
                        bulk_rx_count = 0
                        bulk_tx_count = 0
                        bulk_rx_bytes = 0
                        bulk_tx_bytes = 0
                        
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
                        current_baud = baud
                        print(f"Pkt #{i:5d} | SET_BAUD_RATE: {baud}")
                    elif request == 4: # SET_DATA
                        num_bits = val & 0xFF
                        parity_code = (val >> 8) & 0xF
                        parity_map = {0: "NONE", 1: "ODD", 2: "EVEN", 3: "MARK", 4: "SPACE"}
                        current_parity = parity_map.get(parity_code, "UNKNOWN")
                        print(f"Pkt #{i:5d} | SET_DATA: {num_bits} bits, Parity: {current_parity}")
        
        elif transfer_type == 3: # URB_BULK
            is_in = (endpoint & 0x80) != 0
            payload = pkt[header_len:header_len+data_len]
            if len(payload) > 0:
                if is_in:
                    # Device to Host
                    if len(payload) > 2: # exclude FTDI status bytes
                        bulk_rx_count += 1
                        bulk_rx_bytes += (len(payload) - 2)
                else:
                    # Host to Device
                    bulk_tx_count += 1
                    bulk_tx_bytes += len(payload)
                    
    # Print final accumulated stats
    if bulk_tx_count > 0 or bulk_rx_count > 0:
        print(f"  --> Active Config: Baud={current_baud}, Parity={current_parity}")
        print(f"      Bulk Data: TX={bulk_tx_count} pkts ({bulk_tx_bytes} bytes), RX={bulk_rx_count} pkts ({bulk_rx_bytes} bytes)")

if __name__ == "__main__":
    main()
