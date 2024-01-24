# dhcpstarver
Repo for my Python script used to perform a DHCP Starvation attack by flooding the DHCP Server with bogus DHCPDISCOVER messages. The desired effect is to deplete the DHCP pool configured on the server, preventing other hosts from receiving configuration from the server.  

Also included is the `dhcplistener.py` script, used to detect DHCP Attacks by sniffing DHCP packets.

Written as part of my Engineering Thesis about analysis of DHCP Attacks, and possible detection and preventative measures. Version used in said thesis is at commit #9.

# ⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️
<b>This script was written and is to be used for education and testing purposes only.  

The intent of this script is to test preventative measures against DHCP Starvation attacks. Running this script WILL disrupt your network due to connected devices not being able to obrain IP leases, unless protective measures were applied.  

This script must not be run on anything other than authorized networks, to which you have the right to perform such test (preferrably your own). Running this in any other circumstances may constitute an offence. I am not responsible for any consequences of user actions, e.g. disciplinary, criminal or network disruption, as stated in GPL-3.0 Licence terms. 

Use of this script indicates you acknowledge this warning and licence terms and accept full responsibility.</b>

# DHCP Starver Usage
Usage: `dhcpstarver.py [-h] [-f] [-t TIME] [-s IP] [-l FILE] iface`
```
Positional arguments:
  iface                 Used network interface

Options:
  -h, --help            show this help message and exit
  -f, --full            Complete DORA by replying to DHCPOFFER messages with DHCPREQUEST
  -t TIME, --time TIME  Time between DHCPDISCOVER messages. Default - 0.001s
  -s IP, --server IP    Target IP of DHCP Server. Default - Broadcast
  -l FILE, --log FILE   Enable logging to a text file
```

# DHCP Listener Usage
Under construction

# Todo
- refactor dhcplistener
  - translate to english
  - move from hardcode to argparse
- add GUI to dhcpstarver
- add GUI to dhcplistener
- combine both scripts into single app
- package the scripts into executable
