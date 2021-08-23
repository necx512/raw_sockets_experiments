// man 7 packet

#include <stdio.h>
#include <net/ethernet.h>	/* the L2 protocols */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

int main()
{
    int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));


    /* test reception */
    char packet[4096];
    struct sockaddr rcvaddr;
    struct in_addr addr;
    addr.s_addr = inet_addr("192.168.30.3");	//my ip

    // use nc to send a use packet
    while (1) {
	int len = sizeof(rcvaddr);
	int len_packet =
	    recvfrom(packet_socket, packet, 4096, 0, &rcvaddr, &len);

	// check if the packet is for us
	struct iphdr *iph =
	    (struct iphdr *) (packet + sizeof(struct ethhdr));
	if (iph->daddr != inet_addr("192.168.30.3"))
	    continue;

	// check if tcp
	if (iph->protocol != IPPROTO_TCP)
	    continue;

	// not ssh
	struct tcphdr *tcph =
	    (struct tcphdr *) (packet + sizeof(struct ethhdr) +
			       sizeof(struct iphdr));
	if (tcph->source == htons(22) || tcph->dest == htons(22))
	    continue;

	printf("iph->frag_off: %d.", iph->frag_off);
	printf("Total packet length: %d\n",
	       sizeof(struct ethhdr) + ntohs(iph->tot_len));
    }
}
