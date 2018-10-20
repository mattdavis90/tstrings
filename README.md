# tstrings
Like strings, but packet aware

tstrings uses libwiretap (from tshark) to read packets from a capture file meaning if tshark can open tstrings can. tstrings then searches for strings within each packet. Options to print the packet number and the matching 5-tuple allow you to locate where in the capture file the string is.
## Building
Building tstrings requires

- gcc
- gnumake
- wireshark-devel
- gtk-2-devel
- glibc-devel

The run make
