# dhcpstarver
Repo for my Python script used to perform a DHCP Starvation attack by flooding the DHCP Server with bogus DISCOVER messages. The desired effect is to deplete the DHCP pool configured on the server, preventing other hosts from receiving configuration from the server.  

Written as part of my Engineering Thesis about analysis of DHCP Attacks, and possible detection and preventative measures. Version used in said thesis is at commit #9.

# ⚠️⚠️⚠️ WARNING ⚠️⚠️⚠️
<b>This script was written and is to be used for education and testing purposes only.  

The intent of this script is to test preventative measures against DHCP Starvation attacks. Running this script WILL disrupt your network due to connected devices not being able to obrain IP leases, unless protective measures were applied.  

This script must not be run on anything other than authorized networks, to which you have the right to perform such test (preferrably your own). Running this in any other circumstances may constitute an offence. I am not responsible for any consequences of user actions, e.g. disciplinary, criminal or network disruption, as stated in GPL-3.0 Licence terms. 

Use of this script indicates you acknowledge this warning and licence terms and accept full responsibility.</b>
