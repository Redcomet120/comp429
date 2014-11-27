#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>  /* \  for inet_aton */
#include <arpa/inet.h>   /* /                */

#include <netinet/ip_icmp.h>


double get_time (void) {
	struct timeval tv;
	double d;
	gettimeofday (&tv, NULL);
	d = ((double) tv.tv_usec) / 1000000. + (unsigned long) tv.tv_sec;
	return d;
}

unsigned short calcsum(unsigned short *buffer, int length)
{
	unsigned long sum; 	

	// initialize sum to zero and loop until length (in words) is 0 
	for (sum=0; length>1; length-=2) // sizeof() returns number of bytes, we're interested in number of words 
		sum += *buffer++;	// add 1 word of buffer to sum and proceed to the next 

	// we may have an extra byte 
	if (length==1)
		sum += (char)*buffer;

	sum = (sum >> 16) + (sum & 0xFFFF);  // add high 16 to low 16 
	sum += (sum >> 16);		     // add carry 
	return ~sum;
}

int main(int argc, char* argv[])
{
    if (argc < 2){
	printf("Usage: %s <IP Address>\n",argv[0]);
	exit(1);
    }

    int rc;
    int s = -1;
    struct sockaddr_in addr, raddr;
    socklen_t raddr_len;
    double t1,t2;
    struct iphdr* iphdr = NULL;
    struct icmphdr* icmphdr = NULL;
    char buf[sizeof(struct icmp)];
    char rbuf[sizeof(struct iphdr) + sizeof(struct icmp)];
   
    s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s == -1) {
	perror("socket:");
	exit(1);
    }

    // for now, we only need to supply the ICMP header.
    icmphdr = (struct icmphdr*)buf;

    // first, clear out the ICMP header.
    memset(icmphdr, 0, sizeof(struct icmphdr));

    // now, fill in the parameters for an "echo" request.
    icmphdr->type = ICMP_ECHO;
    icmphdr->un.echo.sequence = 50;
    icmphdr->un.echo.id = 48;
    icmphdr->checksum =
	calcsum((unsigned short*)icmphdr, sizeof(struct icmphdr));

    // prepare the address we're sending the packet to.
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_aton(argv[1], &addr.sin_addr);

    // get timestamp 1 
    t1 = get_time();

    // finally, send the packet.
    rc = sendto(s,
		buf,
		sizeof(struct icmphdr),
		0 /* flags */,
		(struct sockaddr*)&addr,
		sizeof(addr));
   
    if (rc == -1) {
	perror("sendto:");
	exit(1);
    }

    // receive the reply.
    memset(rbuf, 0, sizeof(rbuf));
    raddr_len = sizeof(raddr);
    rc = recvfrom(s, rbuf, sizeof(rbuf), 0, (struct sockaddr*)&raddr, &raddr_len);

    // get timestamp 2
    t2 = get_time();

    if (rc == -1) {
	perror("recvfrom 2:");
	exit(1);
    }

    // we got an IP packet - verify that it contains an ICMP message.
    iphdr = (struct iphdr*)rbuf;
    if (iphdr->protocol != IPPROTO_ICMP) {
	fprintf(stderr, "Expected ICMP packet, got %u\n", iphdr->protocol);
	exit(1);
    }
    
    // verify that it's an ICMP echo reply, with the expected seq. num + id.
    icmphdr = (struct icmphdr*)(rbuf + (iphdr->ihl * 4));
    if (icmphdr->type != ICMP_ECHOREPLY) {
	fprintf(stderr, "Expected ICMP echo-reply, got %u\n", icmphdr->type);
	exit(1);
    }
    else{  // ICMP reply is echo
	printf("Got ICMP echo-reply = %u\n", icmphdr->type);
	printf("Ping is %f\n",t2-t1);
    }
    if (icmphdr->un.echo.sequence != 50) {
	fprintf(stderr,
		"Expected sequence 50, got %d\n", icmphdr->un.echo.sequence);
	exit(1);
    }
    if (icmphdr->un.echo.id != 48) {
	fprintf(stderr,
		"Expected id 48, got %d\n", icmphdr->un.echo.id);
	exit(1);
    }
    printf("Got the expected ICMP echo-reply\n");

    close(s);

    return 0;
}
