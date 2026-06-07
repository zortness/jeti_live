with open("live_capture.pcap", "rb") as f:
    print(f.read(32).hex())
