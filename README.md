## Name and UID

Name: Yuanyuan Xiong

UDI: 405346495

## The high level design of your implementation

The main requirement of this project is to correctly process and forward ARP packets and ICMP packets, so let's talk about the main ideas.

1. When the router receives an Ethernet frame, it must first distinguish whether the type of the frame is ARP or IP packet.

2. When this frame is ARP, it is divided into two cases.

   (1)  When the ARP is a request, a frame needs to be sent to reply to the ARP. In fact, this source IP and source MAC can be added to the Arp Entry at this time.

   (2) When this ARP is a reply, add the received IP and MAC to the Arp Entry, and then send related pending packets.

3. When this frame is an IP packet, it is divided into two cases.

   (1)  When the destination IP address of this IP packet is the IP of an interface of the current router, it must be an ICMP echo. So you need to send an ICMP packet to reply.

   (2) As long as it is not the first case, the packet is forwarded. It is worth noting that the ethernet header needs to be modified when forwarding packets.

4. All frames except for the above cases will be discarded. Other details such as checking checksum etc. will not be repeated.

5. NAT implementation. When the processing of the IP packet, plus several operations. First check whether the IP packet is icmp echo (request), if so, then the packet is sent from the client, and then modify the source IP address of the IP packet. If it is not icmp echo (request), it means that this is a reply from a server, and then modify the destination IP address of the IP packet.



## The problems you ran into and how you solved the problems

Now I will introduce the main problems encountered when implementing functions and solutions.

1. When forwarding an IP packet, if there is no corresponding MAC and IP mapping, the IP packet needs to be added to the pending queue. When only doing this step, the router can also work, but the consequence is that the RTT obtained by the client during the first ping will be extremely large (a few hundred milliseconds). So the key to solving this problem is to send an ARP request after adding this IP packet to the pending queue. Because I wrote the function of sending ARP requests in the method *periodicCheckArpRequestsAndCacheEntries()*, so here I call the *periodicCheckArpRequestsAndCacheEntries()*function. But in fact, this is not correct, because it may conflict with ticker and cause thread insecurity. The correct approach is to write the function of sending ARP requests in a separate method.

2. When I first implemented NAT, the client could not ping the router. The reason is that when the destination IP address of this IP packet is the IP of an interface of the current router, the destination address of this IP packet cannot be modified. Because the IP packet did not go out of the router at all, it just pinged an interface of the router.