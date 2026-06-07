import subprocess
import time
import os
import sys
import struct

# Configuration
USBPcapCMD = r"C:\Program Files\USBPcap\USBPcapCMD.exe"
INTERFACE = r"\\.\USBPcap2"
OUTPUT_PCAP = "live_capture.pcap"

def parse_pcapng_baudrate(filepath):
    # Minimal PCAPNG parser to find SET_BAUD_RATE
    if not os.path.exists(filepath):
        print("Capture file not found.")
        return
        
    found_baud = None
    with open(filepath, 'rb') as f:
        # Check signature
        shb_header = f.read(8)
        if len(shb_header) < 8:
            return
        block_type, block_len = struct.unpack('<II', shb_header)
        if block_type != 0x0A0D0D0A:
            print("Not a valid PCAPNG file.")
            return
            
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
            
            if block_type == 0x00000006: # Enhanced Packet Block
                if len(body) >= 28:
                    header_len = struct.unpack('<H', body[:2])[0]
                    transfer_type = body[22]
                    if transfer_type == 2: # URB_CONTROL
                        if len(body) >= header_len + 8:
                            setup = body[header_len:header_len+8]
                            req_type, request, val, idx, length = struct.unpack('<BBHHH', setup)
                            # FTDI SET_BAUD_RATE
                            if req_type == 0x40 and request == 3:
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
                                print(f"Found SET_BAUD_RATE: {baud} baud (wValue=0x{val:04X}, wIndex=0x{idx:04X})")
                                found_baud = baud
                                
                            # FTDI SET_DATA
                            elif req_type == 0x40 and request == 4:
                                # wValue: bits 7..0: number of bits, bits 11..8: parity, bits 15..12: stop bits
                                num_bits = val & 0xFF
                                parity_code = (val >> 8) & 0xF
                                stop_code = (val >> 12) & 0xF
                                parity_map = {0: "NONE", 1: "ODD", 2: "EVEN", 3: "MARK", 4: "SPACE"}
                                stop_map = {0: "1 stop bit", 1: "1.5 stop bits", 2: "2 stop bits"}
                                print(f"Found SET_DATA config: {num_bits} bits, Parity: {parity_map.get(parity_code, 'UNKNOWN')}, Stop: {stop_map.get(stop_code, 'UNKNOWN')}")
                                
                            # FTDI SET_FLOW_CTRL
                            elif req_type == 0x40 and request == 2:
                                flow_type = (idx >> 8) & 0xFF
                                flow_names = {0: "NONE", 1: "RTS/CTS", 2: "DTR/DSR", 4: "XON/XOFF"}
                                print(f"Found SET_FLOW_CTRL config: {flow_names.get(flow_type, 'UNKNOWN')}")
                                
    return found_baud

def main():
    if not os.path.exists(USBPcapCMD):
        print(f"Error: USBPcapCMD not found at {USBPcapCMD}")
        sys.exit(1)
        
    print("==================================================")
    print("USBPcap Live Capture & Config Extractor")
    print("==================================================")
    print(f"Output file: {OUTPUT_PCAP}")
    print("Preparing to capture from USBPcap interface...")
    
    # We will start the process. Since USBPcapCMD buffers output or captures until killed,
    # we can start it, let the user connect the device/launch Jeti Studio, and then kill it.
    try:
        proc = subprocess.Popen([USBPcapCMD, "-d", INTERFACE, "-o", OUTPUT_PCAP, "-A"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        print(f"Failed to start USBPcapCMD: {e}")
        sys.exit(1)
        
    print("\n>>> CAPTURE STARTED!")
    print(">>> Action Required: Please open Jeti Studio now and connect your JetiBox Profi device.")
    print(">>> Once Jeti Studio successfully connects or logs data (approx. 5-10 seconds),")
    print(">>> press ENTER here to stop the capture.")
    
    # Wait for user input
    input()
    
    print("\nStopping capture...")
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        
    print("Capture stopped. Parsing PCAP to find serial configurations...")
    parse_pcapng_baudrate(OUTPUT_PCAP)

if __name__ == "__main__":
    main()
