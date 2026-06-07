# Jeti ProfiBox Protocol Reverse Engineering Plan

This document outlines the plan to reverse engineer the communication protocol and handshake for the Jeti ProfiBox telemetry device.

## Phase 1: Physical & Environment Setup
1.  **Hardware Connection:** Connect the ProfiBox to your PC via USB/Serial. Identify the COM port (e.g., `COM3` on Windows or `/dev/ttyUSB0` on Linux).
2.  **Signal Analysis (Optional):** Use an oscilloscope or logic analyzer to tap into TX/RX lines of the USB-to-Serial chip to check for hidden signals or noise.
3.  **Software Isolation:** Install Jeti Studio on a dedicated machine or VM to monitor system resources and network activity during communication.

## Phase 2: Passive Observation (The "Sniffing" Phase)
*Goal: Observe what the official software does when it successfully connects.*

1.  **Serial Port Monitoring:** Use tools like **Wireshark** (with USBPcap) or dedicated serial sniffers (**Termite**, **PuTTY**, or **RealTerm**) to capture raw hex data.
2.  **Baseline Capture:** 
    *   Open the sniffer and start logging.
    *   Open Jeti Studio and connect to the ProfiBox.
    *   Observe the "Handshake": Look for a burst of data immediately after connection. Note length, frequency, and repeating patterns (e.g., `0xAA`, `0x55`).
3.  **State Change Correlation:** 
    *   Perform actions in Jeti Studio (change settings, refresh telemetry).
    *   Correlate UI actions with the hex packets sent/received to distinguish "Command" vs. "Telemetry" packets.

## Phase 3: Active Probing (The "Fuzzing" Phase)
*Goal: Interact with the device manually once a baseline is established.*

1.  **Scripted Interaction:** Write a Python script using `pyserial` to send raw hex strings to the COM port.
2.  **Handshake Replication:** Try to replicate the connection sequence observed in Phase 2. If Jeti Studio sends `0x01 0x02 0x03`, try sending it via your script and check for a "Ready" or "Ack" signal.
3.  **Boundary Testing:** 
    *   Send slightly modified versions of the handshake (change one byte at a time).
    *   Observe which changes cause the device to ignore you vs. which ones cause an error response to define checksum and parity logic.

## Phase 4: Protocol Decoding & Mapping
*Goal: Make sense of the telemetry stream.*

1.  **Differential Analysis:** 
    *   Keep the ProfiBox connected to your script (not Jeti Studio).
    *   Move the RC vehicle and record the incoming hex stream.
    *   Look for values that change linearly with movement (e.g., throttle position, steering angle).
2.  **Jeti EX Protocol Alignment:** 
    *   Compare captured data against the published Jeti EX protocol. 
    *   Identify if the ProfiBox uses a modified version of EX or a different framing (start/stop bytes, CRC algorithm).
3.  **Field Mapping Table:** Create a spreadsheet to map:
    *   `Byte Offset` | `Value Range` | `Description` | `Unit`

## Phase 5: Implementation
Once the protocol is mapped, build a lightweight telemetry viewer or integrate it into a custom dashboard.

---

### Summary of Tools Needed:
*   **Hardware:** ProfiBox, USB-to-Serial cable.
*   **Sniffing:** Wireshark + USBPcap, RealTerm (for hex viewing).
*   **Scripting:** Python with `pyserial` and `struct` libraries.
*   **Analysis:** Hex Editor (e.g., HxD).

### Immediate Next Step:
Connect the device, open **RealTerm**, set it to the correct Baud Rate (usually 115200 or 9600), and open **Jeti Studio**. Capture the first 10 seconds of data as a `.bin` or `.txt` file.
