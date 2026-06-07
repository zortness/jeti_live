import sys

def crc16_ref(data: bytes, poly_ref=0x8408, init=0x0000, xor_out=0x0000) -> int:
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
    if len(sys.argv) < 2:
        print("Usage: python calc_crc.py <hex_string>")
        return
    hex_str = sys.argv[1].replace(" ", "")
    data = bytes.fromhex(hex_str)
    crc = crc16_ref(data)
    # LE bytes
    crc_bytes = bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    print(f"CRC-16 (XMODEM/Reflected): 0x{crc:04X} -> bytes: {crc_bytes.hex(' ').upper()}")

if __name__ == "__main__":
    main()
