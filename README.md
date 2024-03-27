# wiresiark
plugins for decoding network packets for Wireshark

## Usage
1. put **.lua** files into wireshark plugins directory e.g. 

(for Unix-like systems):
````shell
~/.config/wireshark/plugins
````
(for Windows):
````shell
C:\Users\[username]\AppData\Roaming\Wireshark
C:\Documents and Settings\username\Application Data\Wireshark
````

2. Set TCP PORT in Configuration section, e.g. 32768
```
---
local PORT = 32768
---
```
3. Run (or restart Wireshark)
4. Capture packets on network interface or open already captured data
5. Should see decoded **SIA Digital Communication** packet

## Supported protocols:

### SIA DC-09

#### Supported tokens:

- **ADM-CID** - Ademco Contact Id


