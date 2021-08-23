A note about fragmentation and MTU:

man 7 raw 
---------

By  default,  raw  sockets do path MTU (Maximum Transmission Unit) discovery.  This means the kernel will keep track of the MTU to a specific target IP address and return EMSGSIZE
       when a raw packet write exceeds it.  When this happens, the application should decrease the packet size.  Path MTU discovery can be  also  turned  off  using  the  IP_MTU_DISCOVER
       socket  option  or  the /proc/sys/net/ipv4/ip_no_pmtu_disc file, see ip(7) for details.  When turned off, raw sockets will fragment outgoing packets that exceed the interface MTU.
       However, disabling it is not recommended for performance and reliability reasons.

If you really want to receive all IP packets, use a packet(7) socket with the ETH_P_IP protocol.  Note that packet sockets don't reassemble IP fragments, unlike raw sockets.



Fragmentation vs Segmentation
-----------------------------
https://www.quora.com/What-is-the-difference-between-fragmentation-and-segmentation-of-packet

Segmentation is for transport layer (like TCP) in order to not exceed the Maximum Segment Size (MSS) which is the maximum size for the transport layer.
Fragmentation is for network layer (like IP) in order to not exced the MTU.

PMTU
----

Path MTU (PMTU) discovery
--------------
/proc/sys/net/ipv4/ip_no_pmtu_disc
https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt


Jumbo Frame
-----------
jumbo frame (MTU 9k)

offload
---------
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/performance_tuning_guide/network-nic-offloads

https://www.ibm.com/docs/en/linux-on-systems?topic=offload-tcp-segmentation


ethtool -k em1
ethtool --offload ens3 tcp-segmentation-offload  off





