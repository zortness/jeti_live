with open("live_capture.pcap", "rb") as f:
    header = f.read(16)
    print("Magic bytes:", header.hex(" ").upper())
