import sys

# Test cases: (data_bytes, expected_crc_bytes)
# Expected CRC bytes are in the order they appear in the packet.
tests = [
    (bytes([0x3E, 0x02, 0x08, 0x00, 0x07, 0x02]), bytes([0x38, 0x63])),
    (bytes([0x3E, 0x02, 0x18, 0x00, 0x0F, 0x16, 0x41, 0x01, 0x00, 0x01, 0x42, 0x01, 0x00, 0x01, 0x45, 0x01, 0x00, 0x01, 0x47, 0x01, 0x00, 0x01]), bytes([0x97, 0xEA])),
    (bytes([0x3E, 0x02, 0x08, 0x00, 0x08, 0x02]), bytes([0xF0, 0xE0])),
    (bytes([0x3E, 0x02, 0x08, 0x00, 0x09, 0x02]), bytes([0x28, 0xF9]))
]

# We need to test common polynomials:
# 0x1021 (CCITT)
# 0x8005 (CRC-16-IBM)
# 0x8408 (CCITT-Reverse)
# 0xA001 (CRC-16-IBM-Reverse)
# 0x3D65
# 0x1EDC6F41 (CRC-32) - wait, it is a 16-bit CRC since there are only 2 bytes of CRC.
polys = [0x1021, 0x8005, 0x8408, 0xA001, 0x3D65, 0xC567, 0x4C57, 0x1005]

def crc16(data, poly, init, ref_in, ref_out, xor_out):
    crc = init
    for b in data:
        if ref_in:
            # Reverse input byte
            b = int('{:08b}'.format(b)[::-1], 2)
        
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
                
    if ref_out:
        # Reverse 16-bit CRC
        crc = int('{:016b}'.format(crc)[::-1], 2)
        
    crc ^= xor_out
    return crc

# Alternative implementation for reversed polynomials (like 0x8408 / 0xA001 where reflection is built-in)
def crc16_ref(data, poly_ref, init, xor_out):
    crc = init
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly_ref
            else:
                crc = crc >> 1
    crc ^= xor_out
    return crc

def main():
    print("Searching CRC-16 parameters...")
    found = False
    
    # Try standard model configurations
    for poly in polys:
        for init in [0x0000, 0xFFFF, 0x1D0F]:
            for ref_in in [False, True]:
                for ref_out in [False, True]:
                    for xor_out in [0x0000, 0xFFFF]:
                        # Verify all tests
                        all_pass_le = True
                        all_pass_be = True
                        
                        for data, expected in tests:
                            crc = crc16(data, poly, init, ref_in, ref_out, xor_out)
                            crc_bytes_le = bytes([crc & 0xFF, (crc >> 8) & 0xFF])
                            crc_bytes_be = bytes([(crc >> 8) & 0xFF, crc & 0xFF])
                            
                            if crc_bytes_le != expected:
                                all_pass_le = False
                            if crc_bytes_be != expected:
                                all_pass_be = False
                                
                        if all_pass_le:
                            print(f"FOUND LE: poly=0x{poly:04X}, init=0x{init:04X}, ref_in={ref_in}, ref_out={ref_out}, xor_out=0x{xor_out:04X}")
                            found = True
                        if all_pass_be:
                            print(f"FOUND BE: poly=0x{poly:04X}, init=0x{init:04X}, ref_in={ref_in}, ref_out={ref_out}, xor_out=0x{xor_out:04X}")
                            found = True

    # Also try the reflected-poly algorithm (which is equivalent but often written differently)
    # Reflected polys are poly reversed (e.g. 0x1021 ref is 0x8408, 0x8005 ref is 0xA001)
    ref_polys = [0x8408, 0xA001, 0x4003]
    for poly_ref in ref_polys:
        for init in [0x0000, 0xFFFF, 0x1D0F, 0xE0B0]:
            for xor_out in [0x0000, 0xFFFF]:
                all_pass_le = True
                all_pass_be = True
                for data, expected in tests:
                    crc = crc16_ref(data, poly_ref, init, xor_out)
                    crc_bytes_le = bytes([crc & 0xFF, (crc >> 8) & 0xFF])
                    crc_bytes_be = bytes([(crc >> 8) & 0xFF, crc & 0xFF])
                    
                    if crc_bytes_le != expected:
                        all_pass_le = False
                    if crc_bytes_be != expected:
                        all_pass_be = False
                        
                if all_pass_le:
                    print(f"FOUND REF LE: poly_ref=0x{poly_ref:04X}, init=0x{init:04X}, xor_out=0x{xor_out:04X}")
                    found = True
                if all_pass_be:
                    print(f"FOUND REF BE: poly_ref=0x{poly_ref:04X}, init=0x{init:04X}, xor_out=0x{xor_out:04X}")
                    found = True
                    
    if not found:
        print("No match found with standard polynomials.")

if __name__ == "__main__":
    main()
