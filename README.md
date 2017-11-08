# OpenCAPWAP v2.0

Open source implementation of the CAPWAP protocol according to RFC 4515 and RFC 4516.
It supports both SplitMAC and LocalMAC operational architectures.

For further informations please refer to: <br />
"OpenCAPWAP v2.0: the new open-source implementation of the CAPWAP protocol", E. Agostini, M. Bernaschi, M. Vellucci, L. Vollero
International Journal of Network Management 2016, Volume 26, Issue 6, Pages 537–552 <br />

[Wiley Online Library](http://onlinelibrary.wiley.com/doi/10.1002/nem.1949/abstract) <br />
[ResearchGate](https://www.researchgate.net/publication/307913953_OpenCAPWAP_v20_the_new_open-source_implementation_of_the_CAPWAP_protocol_OPENCAPWAP_V20)


## Requirements

This version has been tested on Linux Debian distro 32-bit.
You need to install the following libraries:
```
libnl-3-dev
libnl-3-genl-dev
libssl-dev
```

In order to run the WTP software, you must have a wireless card with AP mode available (check with iw)

## Installing

Within the openCAPWAP folder, type:
```
make clean
make
```

For further info, please refer to the INSTALL file

## Notes

OpenCAPWAP doesn't provide any type of DHCP service or IP assignation to associated stations, that is you must have a DHCP server active. When a client station associates with the WTP's AP interface, it starts to send DHCP Discovery messages.
If you are using the SPLIT MAC mode, you must create a bridge between AC's network interface (ethernet or wireless) and the AC's tap interface.
If you are using the LOCAL MAC mode, you must create a bridge between the WTP's AP interface and the ethernet interface.
The DHCP server must be reachable from WTP's ethernet (LOCAL MAC) or AC's ethernet (SPLIT MAC).
