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

def parse_packet(name, payload):
    print(f"\n--- Parsing {name} ---")
    if len(payload) < 2:
        print("Payload too short")
        return
    
    exLength = payload[1] & 0x3F
    exType = (payload[1] >> 6) & 0x03
    print(f"EX Type: {exType} (0=Text, 1=Data, 2=Message), Length: {exLength} bytes following length byte")
    
    productID = payload[2:4]
    deviceID = payload[4:8]
    reserved = payload[8]
    
    print(f"Product ID: {productID.hex().upper()}")
    print(f"Device ID (Serial): {deviceID.hex().upper()}")
    print(f"Reserved: {reserved:02X}")
    
    end_idx = 2 + exLength
    print(f"Telemetry raw bytes: {payload[9:end_idx].hex().upper()}")
    
    is_data = (exLength <= 15)
    
    if is_data:
        idx = 8
        while idx < end_idx:
            firstByte = payload[idx]
            idx += 1
            
            fieldID = firstByte >> 4
            dataType = firstByte & 0x0F
            
            size = getDataTypeSize(dataType)
            if fieldID == 5 and dataType == 4:
                size = 2  # Quirk override: Field 5 DataType 4 is 2 bytes in Jeti receiver
                
            if idx + size > end_idx:
                print(f"  Field header {firstByte:02X} needs size {size} but only {end_idx - idx} bytes left")
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
                
            print(f"  Field {fieldID} (Type {dataType}, Size {size}): Raw {rawBytes.hex().upper()} -> float: {floatVal}, prec: {prec}")
            
    elif exType == 0: # Text
        idx = 10
        if idx < end_idx:
            fieldID = payload[idx]
            idx += 1
            lengths = payload[idx]
            idx += 1
            desc_len = lengths >> 3
            unit_len = lengths & 0x07
            
            desc_bytes = payload[idx : idx + desc_len]
            idx += desc_len
            unit_bytes = payload[idx : idx + unit_len]
            idx += unit_len
            
            desc_str = desc_bytes.decode('ascii', errors='replace')
            unit_str = unit_bytes.decode('ascii', errors='replace')
            print(f"  Text Label for Field {fieldID}: description: {repr(desc_str)} ({desc_len} bytes), unit: {repr(unit_str)} ({unit_len} bytes)")

# Test with the three packets
p1 = bytes.fromhex("410e009f4c81a80d5c6d11f72021f72031")
p2 = bytes.fromhex("4113009f1181a80d5cb3013a54656d702e2041b043e3")
p3 = bytes.fromhex("470f009f4de2a64b54f0113c20200930092a")

parse_packet("p1 (Receiver/Temp data?)", p1)
parse_packet("p2 (Temp Text?)", p2)
parse_packet("p3 (Receiver data)", p3)
