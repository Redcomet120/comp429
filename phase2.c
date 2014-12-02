// http://www.tenouk.com/Module43a.html

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

# define PCKT_LEN 8192
struct ipheader 
{
	unsigned char iph_ihl:5;
	unsigned char iph_ver:4;
	unsigned char      iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned char      iph_flag;
	unsigned short int iph_offset;
	unsigned char      iph_ttl;
	unsigned char      iph_protocol;
	unsigned short int iph_chksum;
	unsigned int       iph_sourceip;
	unsigned int       iph_destip;
};
// now we build the udp head
 struct udpheader 
 {
	unsigned short int udph_srcport;
	unsigned short int udph_destport;
	unsigned short int udph_len;
	unsigned short int udph_chksum;
};

//apparently checksum is important to the tutorial we followed
 unsigned short csum(unsigned short *buf, int nwords)
{
	//
	unsigned long sum;
	for(sum=0; nwords>0; nwords--)
	{
		sum += *buf++;
	}
	sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char *argv[])
{
	int sd;
	//empty payload
	char buffer[PCKT_LEN];
	//headers defined above;
	struct ipheader *ip = (struct ipheader *) buffer;
	struct udpheader *udp = (struct udpHeader *)(buffer + sizeof(struct ipheader));
	// server ip goes here with port
	struct sockaddr_in sin, din;
	int one = 1;
	const int *val = &one;
	int port = 9876;
	
	memset(buffer, 0, PCKT_LEN);
	
	//raw udp socket
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sd ==-1)
	{
		perror("socket failed, we're skrewed");
	}
	else
	{
		printf("we're good with socket\n");
	}
	// set up sin
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr("172.0.0.1");
	// setup din
	din.sin_family = AF_INET;
	din.sin_port = htons(port);
	din.sin_addr.s_addr = inet_addr("172.0.0.1");
	
	//build the ipheader with values
	ip->iph_ihl = 5;
	ip->iph_ver = 4;
	ip->iph_tos = 16;
	ip->iph_len = sizeof(struct ipheader)+ sizeof( struct udpheader);
	ip->iph_ident = htons(54321);
	ip->iph_ttl = 64;
	ip->iph_protocol = 17;
	ip->iph_sourceip = inet_addr("172.0.0.1");
	ip->iph_destip = inet_addr("172.0.0.1");
	
	//build udp header info
	udp->udph_srcport = htons("9876");
	udp->udph_destport = htons("9876");
	//run checksum
	ip->iph_chksum = csum((unsigned short *) buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
	
	// stop the packet structure from being auto filled.
	if(setsockopt (sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
	{
		perror("setsockopt Failed");
	}
	else
	{
		printf("packet head was manually filled \n");
	}
	
	int count;
	for(count = 1; count <=20; count++)
	{
		if(sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&sin, sizeof(sin))==-1)
		{
			perror("sending broke");
		}
		else
		{
			printf("count #%u worked\n",count);
			sleep(2);
		}
	}
	close(sd);
	return 0;
}
