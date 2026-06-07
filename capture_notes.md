Note: these are using an FTDI-FT type device, which may affect the packets
These are from @usbcapture3.pcapng
These blocks all have the byte offset at the beginning of the line with 3 spaces before the data

## normal ping
host: 
```
0000   1b 00 10 80 85 e8 0e e5 ff ff 00 00 00 00 09 00
0010   00 02 00 0a 00 81 03 00 00 00 00
```
device: 
```
0000   1b 00 10 80 85 e8 0e e5 ff ff 00 00 00 00 09 00
0010   01 02 00 0a 00 81 03 02 00 00 00 01 60
```

## every 6th ping
host: 
```
0000   1b 00 a0 52 b1 e8 0e e5 ff ff 00 00 00 00 09 00
0010   00 02 00 0a 00 81 03 00 00 00 00
```
device: 
```
0000   1b 00 a0 52 b1 e8 0e e5 ff ff 00 00 00 00 09 00
0010   01 02 00 0a 00 81 03 1c 00 00 00 01 60 3c 02 1a
0020   00 0f 30 47 0f 00 9f 4d e2 a6 4b 54 f0 11 3c 20
0030   20 09 30 09 2a 56 03
```

## suspect start ping (9 byte response)
host: 
```
0000   1b 00 40 da e0 e3 0e e5 ff ff 00 00 00 00 09 00
0010   00 02 00 0a 00 81 03 00 00 00 00
```
device: 
```
0000   1b 00 40 da e0 e3 0e e5 ff ff 00 00 00 00 09 00
0010   01 02 00 0a 00 81 03 0b 00 00 00 01 60 3c 02 1a
0020   00 0f 30 47 0f 00
```

## possible payloads
host: 
```
0000   1b 00 20 c9 34 08 0f e5 ff ff 00 00 00 00 09 00
0010   00 02 00 0a 00 81 03 00 00 00 00
```
device: 
```
0000   1b 00 20 c9 34 08 0f e5 ff ff 00 00 00 00 09 00
0010   01 02 00 0a 00 81 03 13 00 00 00 01 60 9f 4d e2
0020   a6 4b 54 f0 11 3c 20 20 09 30 09 2a 56 03
```

host: 
```
0000   1b 00 10 a0 2e e8 0e e5 ff ff 00 00 00 00 09 00
0010   00 02 00 0a 00 81 03 00 00 00 00
```
device: 
```
0000   1b 00 10 a0 2e e8 0e e5 ff ff 00 00 00 00 09 00
0010   01 02 00 0a 00 81 03 35 00 00 00 01 60 3c 02 19
0020   00 0f 30 41 0e 00 9f 4c 81 a8 0d 5c 6d 11 f7 20
0030   21 f7 20 31 6d 20 3c 02 1a 00 0f 30 47 0f 00 9f
0040   4d e2 a6 4b 54 f0 11 3c 20 20 09 30 09 2a 56 03
```

host: 
```
0000   1b 00 10 c0 3d ea 0e e5 ff ff 00 00 00 00 09 00
0010   00 02 00 0a 00 81 03 00 00 00 00
```
device:
```
0000   1b 00 10 c0 3d ea 0e e5 ff ff 00 00 00 00 09 00
0010   01 02 00 0a 00 81 03 3a 00 00 00 01 60 3c 02 1e
0020   00 0f 30 41 13 00 9f 11 81 a8 0d 5c b3 01 3a 54
0030   65 6d 70 2e 20 41 b0 43 e3 af 49 3c 02 1a 00 0f
0040   30 47 0f 00 9f 4d e2 a6 4b 54 f0 11 3c 20 20 09
0050   30 09 2a 56 03
```


