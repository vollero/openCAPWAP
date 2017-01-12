# OpenCAPWAP v2.0

Open source implementation of the CAPWAP protocol according to RFC 4515 and RFC 4516.
It supports both SplitMAC and LocalMAC operational architectures.

For further informations please refer to: 
"OpenCAPWAP v2.0: the new open-source implementation of the CAPWAP protocol", E. Agostini, M. Bernaschi, M. Vellucci, L. Vollero
International Journal of Network Management 2016, 26:537–552

## Requirements

You need to install the following libraries:
```
libnl-3-dev
libnl-3-genl
libssl-dev
```

In order to run the WTP software, you must have a wireless card with AP mode available (check with iw)

## Installing

Within the openCAPWAP folder, type:
```
make clean
make
```

## Notes

OpenCAPWAP doesn't provide any type of DHCP service or IP assignation to associated stations, that is you must have a DHCP server active. When a client station associates with the WTP's AP interface, it starts to send DHCP Discovery messages.
If you are using the SPLIT MAC mode, you must create a bridge between AC's network interface (ethernet or wireless) and the AC's tap interface.
If you are using the LOCAL MAC mode, you must create a bridge between the WTP's AP interface and the ethernet interface.
The DHCP server must be reachable from WTP's ethernet (LOCAL MAC) or AC's ethernet (SPLIT MAC).