// man 7 ip

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
int main()
{
	int packet_socket = socket(AF_INET, SOCK_STREAM, 0); 

        struct sockaddr_in socket_address;
	   memset (&socket_address, 0, sizeof (struct sockaddr_in));
	   socket_address.sin_family = AF_INET;
	   socket_address.sin_port = htons(12345);
	   socket_address.sin_addr.s_addr = inet_addr("192.168.50.1");

	   if(connect(packet_socket,(struct sockaddr *) &socket_address, sizeof(struct sockaddr_in)) == -1)
           {
               perror("connect()");
               exit(-1);
           }



       for(int len_data=1599; len_data < 1600; len_data++)
       {
	   int len_packet = len_data;
	   printf("len_packet: %d (%d)\n",len_packet,len_packet+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr));

           char *packet = malloc(len_packet);
	   memset(packet,'a',len_packet);

	   char *data = (char *) packet + len_packet - len_data;
  

	   assert(send(packet_socket, data,len_data,0) != -1);
	   usleep(10000);
       }










}
