import struct
import sys

sys.stdout.reconfigure(encoding='utf-8')

def decode6b(valByte):
    sign = -1 if (valByte & 0x80) != 0 else 1
    precision = (valByte & 0x60) >> 5
    absVal = valByte & 0x1F
    val = absVal * sign
    
    if precision == 1:
        return val / 10.0, precision, val
    elif precision == 2:
        return val / 100.0, precision, val
    else:
        return float(val), precision, val

def decode14b(low, high):
    sign = -1 if (high & 0x80) != 0 else 1
    precision = (high & 0x60) >> 5
    absVal = low | ((high & 0x1F) << 8)
    val = absVal * sign
    
    if precision == 1:
        return val / 10.0, precision, val
    elif precision == 2:
        return val / 100.0, precision, val
    else:
        return float(val), precision, val

def decode22b(low, mid, high):
    sign = -1 if (high & 0x80) != 0 else 1
    precision = (high & 0x60) >> 5
    absVal = low | (mid << 8) | ((high & 0x1F) << 16)
    val = absVal * sign
    
    if precision == 1:
        return val / 10.0, precision, val
    elif precision == 2:
        return val / 100.0, precision, val
    else:
        return float(val), precision, val

def getDataTypeSize(dataType):
    if dataType == 0:
        return 1
    elif dataType in (1, 2, 3):
        return 2
    elif dataType in (4, 5, 6, 7):
        return 3
    elif dataType in (8, 9, 10, 11):
        return 4
    elif dataType == 12:
        return 1
    else:
        return 2

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

# Parse and display unique telemetry values
seen_values = set()
for jp in jeti_packets:
    if len(jp) < 8:
        continue
    cmd_type = jp[5]
    payload = jp[6:-2]
    
    if len(payload) < 2:
        continue
        
    exLength = payload[1] & 0x3F
    exType = (payload[1] >> 6) & 0x03
    
    # Check if this is a data packet
    # Since payload[1] is length, let's treat payload[1] <= 15 as Data
    if exLength <= 15:
        # Data packet
        productID = payload[2:4]
        deviceID = payload[4:8]
        end_idx = 2 + exLength
        
        idx = 8
        fields_str = []
        while idx < end_idx:
            firstByte = payload[idx]
            idx += 1
            
            fieldID = firstByte >> 4
            dataType = firstByte & 0x0F
            
            size = getDataTypeSize(dataType)
            if idx + size > end_idx:
                break
                
            rawBytes = payload[idx : idx + size]
            idx += size
            
            if size == 1:
                floatVal, prec, rawVal = decode6b(rawBytes[0])
            elif size == 2:
                floatVal, prec, rawVal = decode14b(rawBytes[0], rawBytes[1])
            elif size == 3:
                floatVal, prec, rawVal = decode22b(rawBytes[0], rawBytes[1], rawBytes[2])
            else:
                floatVal, prec, rawVal = 0.0, 0, 0
                
            fields_str.append(f"F{fieldID}: {floatVal} (Raw: {rawBytes.hex().upper()})")
        
        dev_str = deviceID.hex().upper()
        res_str = f"Dev: {dev_str} -> " + ", ".join(fields_str)
        if res_str not in seen_values:
            seen_values.add(res_str)
            print(res_str)
