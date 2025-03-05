#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/udp.h> //Provides declarations for udp header
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h>	

struct network_flow
{
	char *sourceIP;
	char *destIP;
	int sourcePort;
	int destPort;
	int protocol; //1 for TCP, 2 for UDP
};

typedef struct network_flow NF;

/* Some Global Variables. */
int total_packet = 0;
int udp=0;
int tcp=0;
int tcp_bytes=0;
int udp_bytes=0;

int count_NFs=0;
int count_TCP_NFs=0;
int count_UDP_NFs=0;

NF *nf;


void update_network_flow(char *sIP, char *dIP, int sP, int dP, int p)
{
	//The First network flow.
	if(count_NFs == 0)
	{
		nf = (NF *)malloc(sizeof(NF));
		nf[0].sourceIP = (char *)malloc(sizeof(char)*(strlen(sIP)+1));
		nf[0].destIP = (char *)malloc(sizeof(char)*(strlen(dIP)+1));
		strcpy(nf[0].sourceIP, sIP);
		strcpy(nf[0].destIP, dIP);
		nf[0].sourcePort = sP;
		nf[0].destPort = dP;
		nf[0].protocol = p;
		count_NFs++;
		return;
	}

	//Check if network flow exists.
	int isExist = 0;
	int i=0;
	while(i<count_NFs)
	{
		if( strcmp(nf[i].sourceIP,sIP)==0 && strcmp(nf[i].destIP,dIP)==0 && 
			nf[i].sourcePort==sP && nf[i].destPort==dP && nf[i].protocol==p )
		{
			isExist=1;
			break;
		}
		i++;
	}
	//If not exists, then update.
	if(!isExist)
	{
		nf = (NF *)realloc(nf, sizeof(NF)*(count_NFs+1));
		nf[count_NFs].sourceIP = (char *)malloc(sizeof(char)*(strlen(sIP)+1));
		nf[count_NFs].destIP = (char *)malloc(sizeof(char)*(strlen(dIP)+1));
		strcpy(nf[count_NFs].sourceIP, sIP);
		strcpy(nf[count_NFs].destIP, dIP);
		nf[count_NFs].sourcePort = sP;
		nf[count_NFs].destPort = dP;
		nf[count_NFs].protocol = p;
		count_NFs++;
		if(p==1)
			count_TCP_NFs++;
		else
			count_UDP_NFs++;
	}
}

void udp_packet(const u_char *buf, int size)
{
	unsigned short ip_hdr_len;
	struct sockaddr_in source, dest;
	struct iphdr *ip_head = (struct iphdr *)(buf +  sizeof(struct ethhdr));
	ip_hdr_len = ip_head->ihl*4;

	struct udphdr *udp_hdr = (struct udphdr *)(buf + ip_hdr_len + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + ip_hdr_len + sizeof(udp_hdr);

	printf("=====================================================\n");
	//Step 5. Source and Dest IP Address.
	memset(&source, 0, sizeof(source));
	memset(&dest, 0, sizeof(dest));

	source.sin_addr.s_addr = ip_head->saddr;
	dest.sin_addr.s_addr = ip_head->daddr;

	printf("Source IP: %s\n" , inet_ntoa(source.sin_addr));
	printf("Destination IP: %s\n" , inet_ntoa(dest.sin_addr));

	//Step 6. Source and Dest Port Number.
	printf("Source Port: %d\n" , ntohs(udp_hdr->source));
	printf("Destination Port: %d\n" , ntohs(udp_hdr->dest));

	//Step 7. Packet's Protocol.
	printf("Protocol: %d\n", (unsigned int)ip_head->protocol);

	//Step 8. Print the packet’s TCP/UDP header length and TCP/UDP payload length in bytes.
	printf("UDP Header Length: %ld bytes.\n" , sizeof(udp_hdr));
	int payload_size = size - header_size;
	printf("UDP Payload Length: %d bytes.\n" , payload_size);

	update_network_flow(inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr), ntohs(udp_hdr->source), ntohs(udp_hdr->dest), 2);
}

void tcp_packet(const u_char *buf, int size)
{
	unsigned short ip_hdr_len;
	struct sockaddr_in source, dest;
	struct iphdr *ip_head = (struct iphdr *)(buf +  sizeof(struct ethhdr));
	ip_hdr_len = ip_head->ihl*4;

	struct tcphdr *tcp_hdr = (struct tcphdr *)(buf + ip_hdr_len + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr->doff*4;

	printf("=====================================================\n");
	//Step 5. Source and Dest IP Address.
	memset(&source, 0, sizeof(source));
	memset(&dest, 0, sizeof(dest));

	source.sin_addr.s_addr = ip_head->saddr;
	dest.sin_addr.s_addr = ip_head->daddr;

	printf("Source IP: %s\n" , inet_ntoa(source.sin_addr));
	printf("Destination IP: %s\n" , inet_ntoa(dest.sin_addr));

	//Step 6. Source and Dest Port Number.
	printf("Source Port: %d\n" , ntohs(tcp_hdr->source));
	printf("Destination Port: %d\n" , ntohs(tcp_hdr->dest));

	//Step 7. Packet's Protocol.
	printf("Protocol: %d\n", (unsigned int)ip_head->protocol);

	//Step 8. Print the packet’s TCP/UDP header length and TCP/UDP payload length in bytes.
	printf("TCP Header Length: %d bytes.\n" , (unsigned int)tcp_hdr->doff*4);
	int payload_size = size - header_size;
	printf("TCP Payload Length: %d bytes.\n" , payload_size);

	update_network_flow(inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr), ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest), 1);

}

void process_packet(u_char *user_data, const struct pcap_pkthdr *pkt_header, const u_char *packet)
{	
	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
	int size = pkt_header->len; //That is the packet's full size in bytes.
	total_packet++;

	//Step 3/4->Decode Packet/Skip if not UDP or TCP.
	if(iph->protocol == 17) //It is UDP
	{
		udp++;
		udp_bytes += size;
		udp_packet(packet, size);
	}
	else if(iph->protocol == 6)//It is TCP
	{
		tcp_packet(packet, size);
		tcp_bytes += size;
		tcp++;
	}
	else //Skip this Packet.
		return;
}

/*
	Print some information about interfaces
*/
void info_IFace(void)
{
	printf("\n\tAvailable Network Interfaces/Devices\n");
	printf("-----------------------------------------------\n");
	system("nmcli device status");
	printf("-----------------------------------------------\n");
}

void Capture_Network_Packets(const char *IFace, int mode)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask; /* Our netmask */
	bpf_u_int32 net;  /* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	pcap_t *handle;
	const u_char *packet;		/* The actual packet */

	
	if(mode == 0)
	{
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(IFace, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) 
		{
			fprintf(stderr, "Couldn't open device %s: %s\n", IFace, errbuf);
			info_IFace();
			exit(2);
		}
	}
	else
	{
		handle = pcap_open_offline(IFace, errbuf);
		if (handle == NULL) 
		{
			fprintf(stderr, "Couldn't open device %s: %s\n", IFace, errbuf);
			info_IFace();
			exit(2);
		}
	}
	time_t end;
    time_t start = time(NULL);
    time_t seconds = 61*5; // end loop after this time has elapsed.Atleast 5 minutes of capture.
    end = start + seconds;

    // Grab packets for certain time.
    while(start<end)
    {
    	/* Grab packet to decode them.*/
		pcap_loop(handle, 1, process_packet, NULL);
    	start = time(NULL);
    }
	pcap_close(handle);

}

void usage(void)
{
	printf(
		   "Options:\n"
		   "-i <X>, Network interface name (e.g.,-i eth0).\n"
		   "-r <X>, Packet capture file name (e.g.,-r test.pcap).\n"
		   "-a, Available Network Interfaces and some Information.\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

int main(int argc, char *argv[])
{

	int ch;

	if (argc < 2)
		usage();

	while((ch = getopt(argc, argv, "hai:r:")) != -1) 
	{
		switch (ch) 
		{		
			case 'i':
				Capture_Network_Packets(optarg, 0);
				break;
			case 'r':
				Capture_Network_Packets(optarg, 1);
				break;
			case 'a':
				info_IFace();
				break;
			default:
				usage();
		}

	}

	printf("\n=======================Statistics====================\n");
	printf("Total number of network flows captured​: %d\n", count_NFs);
	printf("Number of TCP network flows captured: %d\n", count_TCP_NFs);
	printf("Number of UDP network flows captured: %d\n", count_UDP_NFs);
	printf("Total number of packets received: %d\n", total_packet);
	printf("Total number of TCP packets received: %d\n", tcp);
	printf("Total number of UDP packets received: %d\n", udp);
	printf("Total bytes of TCP packets received: %d\n", tcp_bytes);
	printf("Total bytes of UDP packets received: %d\n", udp_bytes);
	printf("=====================================================\n");

	//Free struct NF
	for(int i=(count_NFs-1); i=0; i--)
	{
		free(nf[i].sourceIP);
		free(nf[i].destIP);
		free(&(nf[i]));
	}

	free(nf);
	return 0;
}