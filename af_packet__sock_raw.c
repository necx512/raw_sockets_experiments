// man 7 packet

#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


int lendata;
unsigned char *data;
struct pseudo_header
{
        u_int32_t source_address;
        u_int32_t dest_address;
        u_int8_t placeholder;
        u_int8_t protocol;
        u_int16_t length;
};

static unsigned short csum(unsigned short *ptr,int nbytes)
{
        register long sum;
        unsigned short oddbyte;
        register short answer;

        sum=0;
        while(nbytes>1) {
                sum+=*ptr++;
                nbytes-=2;
        }
        if(nbytes==1) {
                oddbyte=0;
                *((u_char*)&oddbyte)=*(u_char*)ptr;
                sum+=oddbyte;
        }

        sum = (sum>>16)+(sum & 0xffff);
        sum = sum + (sum>>16);
        answer=(short)~sum;

        return(answer);
}

void update_ip_sum(unsigned char *packet)
{
    struct iphdr *iph = (struct iphdr *) packet;
    iph->check = 0;
    iph->check = csum ((unsigned short *) iph, sizeof (struct iphdr));
}

void update_tcpudp_sum(unsigned char *packet,int len_packet, u_int8_t protocol)
{
        struct iphdr *iph = (struct iphdr *) packet ;
        unsigned char *layer4h = packet + sizeof (struct iphdr);
	struct tcphdr *tcph = (struct tcphdr *)layer4h;
	struct udphdr *udph = (struct udphdr *)layer4h;

	if(protocol == IPPROTO_UDP)
		udph->check = 0;
	else
		tcph->check = 0;


        struct pseudo_header psh;

        psh.source_address = iph->saddr;
        psh.dest_address = iph->daddr;
        psh.placeholder = 0;
        psh.protocol = protocol;

	int len_from_layer4_level=len_packet-sizeof(struct iphdr);
        psh.length = htons(len_from_layer4_level) ;
        int psize = sizeof(struct pseudo_header) + len_from_layer4_level;
        char *pseudogram = malloc(psize);
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , layer4h , len_from_layer4_level);
	if(protocol == IPPROTO_UDP)
		udph->check = csum( (unsigned short*) pseudogram , psize);
	else
                tcph->check = csum( (unsigned short*) pseudogram , psize);
        free(pseudogram);

}

struct iphdr *fill_ip_after_eth(unsigned char *packet, int lenpacket, char *src_ip, char *dst_ip, u_int8_t protocol)
{
        struct iphdr *iph = (struct iphdr *)(packet+sizeof(struct ethhdr));
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(lenpacket-sizeof(struct ethhdr));
        iph->id = htons(rand()&0xffff);        //Id of this packet
        iph->frag_off = 0x40;
        iph->ttl = 64;
	iph->protocol = protocol;
        iph->saddr = inet_addr (src_ip);        //Spoof the source ip address
        iph->daddr = inet_addr (dst_ip);

	update_ip_sum(packet+sizeof(struct ethhdr));

	return iph;
}

unsigned char *fill_transport_layer_after_ip(unsigned char *packet, int lenpacket, u_int8_t protocol, short src_port, short dst_port)
{
    unsigned char *layer4h = packet + sizeof(struct ethhdr) + sizeof (struct iphdr);
    struct tcphdr *tcph = (struct tcphdr *)layer4h;
    struct udphdr *udph = (struct udphdr *)layer4h;

    int len_layer4_header_included = lenpacket - sizeof (struct iphdr) - sizeof(struct ethhdr);
	

    if(protocol == IPPROTO_UDP)
    {
      udph->source = htons (src_port);
      udph->dest = htons (dst_port);
      udph->len = htons(len_layer4_header_included);       //header size
    }
    else
    {
      tcph->source = htons (src_port);
      tcph->dest = htons (dst_port);
      tcph->seq = htonl(1);
      tcph->ack_seq = 0;

      tcph->res1=0;
      tcph->res2=0;
      tcph->doff= (unsigned char)(sizeof (struct tcphdr) / 4);
      printf("%d\n",tcph->doff);
      tcph->fin=0;
      tcph->syn=1;
      tcph->rst=0;
      tcph->psh=0;
      tcph->ack=0;
      tcph->urg=0;

    }

    update_tcpudp_sum(packet+sizeof(struct ethhdr), lenpacket-sizeof(struct ethhdr) , protocol);

    return layer4h;

}

int is_tcp_or_udp_over_ip(unsigned char *packet)
{
    struct ethhdr *eh = (struct ethhdr *) packet;
    if( eh->h_proto == htons(ETH_P_IP))
    {
        struct iphdr *iph = (struct iphdr *) (packet + sizeof (struct ethhdr));
        if(iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
        {
            return 1;
        }
    }
    return 0;
}
int eq_addr(unsigned char *packet, const struct in_addr addr, int src)
{
    struct ethhdr *eh = (struct ethhdr *) packet;
    if( eh->h_proto == htons(ETH_P_IP))
    {
        struct iphdr *iph = (struct iphdr *) (packet + sizeof (struct ethhdr));
        if( (src == 1 && addr.s_addr == iph->saddr) || (src == 0 && addr.s_addr == iph->daddr) )
        {
            return 1;
        }
    }
    return 0;
}
int get_packet_size_from_ip(unsigned char *packet)
{
    struct ethhdr *eh = (struct ethhdr *) packet;
    if( eh->h_proto == htons(ETH_P_IP))
    {
	    struct iphdr *iph = (struct iphdr *) (packet + sizeof (struct ethhdr));
	    return sizeof(struct ethhdr) + ntohs(iph->tot_len);
    }
    return -1;

}
int is_tcp_port(unsigned char *packet, short port)
{
    struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof (struct ethhdr) + sizeof(struct iphdr));
    if(tcph->source == htons(port) || tcph->dest == htons(port))
	    return 1;
    return 0;
}
int main(int argc, char *argv[])
{
	int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)); 


	/* test reception */
	unsigned char packet[4096];
	struct sockaddr rcvaddr;
	struct in_addr addr;
        addr.s_addr = inet_addr("192.168.30.3");

	// use nc to send a use packet
	/*while(1)
	{
	  int len = sizeof (rcvaddr);
	  int len_packet = recvfrom(packet_socket, packet, 4096,0,&rcvaddr,&len);
          if(len_packet > 0 && is_tcp_or_udp_over_ip(packet) == 1 && eq_addr(packet,addr,0) == 1)
	  {
		  if(is_tcp_port(packet, 22) == 0)
 		    printf("%d\n",get_packet_size_from_ip(packet));
	  }
	}*/
	/*
	unsigned char mac_gw_direct[]={0x0c,0x7e,0x08,0x9e,0xde,0x02};

	struct sockaddr_ll socket_address; // we need this kind of structure according man 7 packet
	memset(&socket_address,0,sizeof(struct sockaddr_ll));
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_IP);///usr/include/linux/if_ether.h 
        socket_address.sll_ifindex = 5 ;
        socket_address.sll_halen = ETH_ALEN; // length of destination mac address
	for(int i=0;i<6;++i)
          socket_address.sll_addr[i] = mac_gw_direct[i];

       for(int len_data=0; len_data < 1600; len_data++)
       {
	   int len_packet = sizeof(struct iphdr) + sizeof(struct udphdr) + len_data;
	   printf("len_packet: %d (%d)\n",len_packet,len_packet+sizeof(struct ethhdr));

           char *packet = malloc(len_packet);

	   struct iphdr *iph = fill_ip_after_eth(packet, len_packet, "192.168.10.1", "192.168.50.1", IPPROTO_UDP);

	   struct udp_hdr *udph = (struct udp_hdr *)fill_transport_layer_after_ip(packet, len_packet, IPPROTO_UDP, 12345, 54321);

	   char *data = (char *) packet + len_packet - len_data;
  

           if(sendto (packet_socket, packet, len_packet , 0, (struct sockaddr *) &socket_address, sizeof (socket_address)) < 0) // cannot send more than MTU (ethernet header included)
           {
                   perror("sendto");
		   break;
           }
	   usleep(1000);
       }*/

	// send
	//
	int totalsize=atoi(argv[1]);
	lendata = totalsize - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr);
	data = packet + totalsize - lendata;

	unsigned char mac1[]={0x0c,0x7e,0x08,0x31,0x12,0x03}; // 192.168.10.1
	
	unsigned char mac2[]={0x0c,0x7e,0x08,0x9e,0xde,0x02}; // 192.168.10.2
	unsigned char mac3[]={0x0c,0x7e,0x08,0x9e,0xde,0x01}; // 192.168.30.1

	unsigned char mac4[]={0x0c,0x7e,0x08,0xbc,0x6f,0x00}; // 192.168.30.3

	unsigned char mac5[]={0x0c,0x7e,0x08,0x49,0x13,0x00}; // 192.168.30.4

	for(int i=0;i<6;++i)
	{
		packet[i] = mac3[i];//dst
		packet[6+i] = mac4[i];//src
	}

	packet[12] = 0x08;
	packet[13] = 0x00;

        memset(data,'b', lendata);
	data[lendata-2] = 'c';
	data[lendata-1] = '\n';

	fill_ip_after_eth(packet, totalsize, "192.168.30.3", "192.168.10.1", IPPROTO_UDP);
	fill_transport_layer_after_ip(packet, totalsize, IPPROTO_UDP, 12345, 54321);
	

	struct sockaddr_ll socket_address;
	socket_address.sll_ifindex = 2;
	socket_address.sll_halen = ETH_ALEN;
	socket_address.sll_addr[0]=packet[0];
	socket_address.sll_addr[1]=packet[1];
	socket_address.sll_addr[2]=packet[2];
	socket_address.sll_addr[3]=packet[3];
	socket_address.sll_addr[4]=packet[4];
	socket_address.sll_addr[5]=packet[5];

	assert(sendto(packet_socket,packet,totalsize,0,(struct sockaddr *)&socket_address, sizeof(socket_address)) != -1);







}
