# AddressSync

This Ghidra Module allows external program to select current address (in the Ghidra Listing/Decompiler views) via a UDP message sent to port 1080 containing a 64-bit little endian address.

This is a crude simplification of the [GDB Ghidra Bridge](https://github.com/Comsecuris/gdbghidra) plugin that's sufficient enough for my purposes (i.e. sync'ing PC state from [aemulari](https://github.com/jynik/aemulari)) and simple enough to quickly shoehorn into little tools and scripts.

## Build

* Setup the GhidraDev environment and create a new project
* Add the `*.java` files here to the project, replacing the boilerplate.
* Build with Eclipse (or gradle)
