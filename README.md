# wiresiark
Wireshark plugins for decoding network packets

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

<p align="center">
  <img src="https://github.com/pa810p/wiresiark/assets/46489402/4de4c3a2-be6a-49b4-bb2a-1f46efa49f24">
</p>

## Supported protocols:

### SIA DC-09
<p align="center">
  <img src="https://github.com/pa810p/wiresiark/assets/46489402/2e724cab-fb89-4fae-83bc-7eb73e022a4d">
</p>

#### Supported contents:

- **ADM-CID** - Ademco Contact Id, DC-05 Format

<p align="center">
  <img src="https://github.com/pa810p/wiresiark/assets/46489402/296937c1-a278-4d7c-9c04-9cd1bac63212">  
</p>

---



