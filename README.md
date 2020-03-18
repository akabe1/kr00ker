kr00ker
============


# Description 
This script is a simple experiment to exploit the KR00K vulnerability (CVE-2019-15126), 
that allows to decrypt some WPA2 CCMP data in vulnerable devices.
More specifically this script attempts to retrieve Plaintext Data of WPA2 CCMP packets knowning:
 * the TK (128 bites all zero) 
 * the Nonce (sent plaintext in packet header)
 * the Encrypted Data

 Where:
 * WPA2 AES-CCMP decryption --> AES(Nonce,TK) XOR Encrypted Data = Decrypted Data  
 * Decrypted stream starts with "\xaa\xaa\x03\x00\x00\x00"
 * Nonce (104 bits) = Priority (1byte) + SRC MAC (6bytes) + PN (6bytes)


# References:
* https://www.welivesecurity.com/wp-content/uploads/2020/02/ESET_Kr00k.pdf


# Limitations
To check the Kr00k vulnerability it coulb be necessary to launch the PoC multiple times, because (it seems that) not always
a sufficient amount of data is buffered on vulnerable devices (hint: try using streaming apps).

# Notes
This script must be run as privileged user and with wireless interface configured in monoitor mode


# Dependencies
The installation of the Python packages "scapy" and "Cryptodome" is required.
The script is compatible with Python 3.



# Usage
Following are reported some usage examples of the tool. 
Use the "--help" option for a more exhaustive list.


Launch the Kr00k attack against the client (-t client) device:
```
# python3 kr00ker.py -i <interface-name> -s <SSID> -c <MAC-client> -n <num-packets> -r <reason-id> -t client -w <wifi-channel> -d <delay>
```
or launch the Kr00k attack against the Access Point (-t ap) device:
```
$ sudo python3 kr00ker.py -i <interface-name> -s <SSID> -c <MAC-client> -n <num-packets> -r <reason-id> -t ap -w <wifi-channel> -d <delay>
```


# Author
kr00ker was developed by Maurizio Siddu



# GNU License
Copyright (c) 2020 kr00ker

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>

