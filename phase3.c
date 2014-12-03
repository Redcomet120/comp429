
#include <signal.h>
#include <stdio.h> //for printf
#include <string.h> //memset
#include <sys/socket.h>    //for socket ofcourse
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/ip_icmp.h>
#include <unistd.h> 
#include <sys/time.h>
#include <sys/prctl.h>

#define RANDPATH "/dev/urandom"

/*  Just returns current time as double, with most possible precision...  */
double get_time (void) {
	struct timeval tv;
	double d;
	gettimeofday (&tv, NULL);
	d = ((double) tv.tv_usec) / 1000000. + (unsigned long) tv.tv_sec;
	return d;
}


uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint64_t acc=0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset) {
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }

    // Handle any complete 32-bit blocks.
    char* data_end=data+(length&~3);
    while (data!=data_end) {
        uint32_t word;
        memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;

    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word=0;
        memcpy(&word,data,length);
        acc+=ntohl(word);
    }

    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16) {
        acc=(acc&0xffff)+(acc>>16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1) {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}
 
int main(int argc, char* argv[])
{
    
    unsigned int rand;
    FILE *f;
    if (argc != 9){
       printf("Usage: %s <IP Address>\n",argv[0]);
       exit(1);
    }
    
    //get command line values
    char dest_IP[32];  
    char entropy[3];
    strcpy(dest_IP,argv[1]);
    int dest_port = atoi(argv[2]);
    strcpy(entropy,argv[3]);
    int load_size = atoi(argv[4]);
    int load_num = atoi(argv[5]);
    int ttl = atoi(argv[6]);
    int sleep_time = atoi(argv[7]);
    int icmp_num = atoi(argv[8]);

    double t1,t2;    
    int rc = -1;
    int i;
    struct sockaddr_in raddr;
    socklen_t raddr_len;
    //Create a raw socket of type IPPROTO
    int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
     
    if(s == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create raw socket");
        exit(1);
    }
    int t = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if(t == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create receive raw socket");
        exit(1);
    }

    
    //Datagram to represent the packet
    char datagram[4096] , word[load_size], source_ip[32] , *data;
    //change datagram size to sizeofdata maybe
    //zero out the packet buffer
    memset (datagram, 0, 4096);
    memset (word, 0, load_size);
     
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;

    //ICMP stuff
    struct icmphdr* icmphdr = NULL;
    char buf[sizeof(struct icmp)]; 
    char rbuf[sizeof(struct iphdr) + sizeof(struct icmp)];  

    //UDP header
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
     
    struct sockaddr_in sin, addr;
       
    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);

    if (strcmp(entropy,"H") == 0)
    {
	f = fopen(RANDPATH, "r");
        for (i = 0; i < load_size; i++){
            fread(&rand,sizeof(rand),1,f);
    	    word[i] = (char)rand%2;
        }
        fclose(f);
    }
    else if (strcmp(entropy,"L") == 0)
    {
    	for (i = 0; i < load_size; i++){
            word[i] = (char)0;
        }
    }
    strcpy(data , "ART");
     
    //some address resolution
    strcpy(source_ip , "192.168.1.2");
     
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr (dest_IP);
     
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    iph->id = htonl (54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = ttl;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;
     
    //Ip checksum
    iph->check = ip_checksum ((unsigned short *) datagram, iph->tot_len);
     
    //UDP header
    udph->source = htons (6666);
    udph->dest = htons (dest_port);
    udph->len = htons(8 + strlen(data)); //udp header size
    udph->check = 0; //leave checksum 0 now, filled later by pseudo header
    
    //create icmp message
    
    icmphdr = (struct icmphdr*)buf;
    // first, clear out the ICMP header.
    memset(icmphdr, 0, sizeof(struct icmphdr));
    // now, fill in the parameters for an "echo" request.
    icmphdr->type = ICMP_ECHO;
    icmphdr->un.echo.sequence = 50;
    icmphdr->un.echo.id = 48;
    icmphdr->checksum = ip_checksum((unsigned short*)icmphdr, sizeof(struct icmphdr));
    // prepare the address we're sending the packet to.
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_aton(dest_IP, &addr.sin_addr);
     
    pid_t pid = fork();
    if (pid == 0)  //sender
    {
        prctl(PR_SET_PDEATHSIG, SIGHUP); //kill this process when parent exits
        //send initial packet
        sendto(t, buf, sizeof(struct icmphdr), 0 /* flags */, (struct sockaddr*)&addr, sizeof(addr));
	
	for(i = 0; i < load_num; i++){
        //Send the packet
           if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
           {
              perror("sendto failed");
           }
           //Data send successfully
           else
           {
              printf ("Packet Send. Length : %d \n" , iph->tot_len);
           }
        }
        for (i = 0; i < icmp_num; i++){
           //Send final packets
           sendto(t, buf, sizeof(struct icmphdr), 0 /* flags */, (struct sockaddr*)&addr, sizeof(addr));
           sleep(sleep_time);
        }
        close(s);
    }
    else  //receiver
    {
        int count = 0;
	while(1){
           rc = recvfrom(t, rbuf, sizeof(rbuf) ,  0, (struct sockaddr *)&raddr, &raddr_len); 
           struct iphdr* iphdr = NULL;
           struct icmphdr* icmphdr = NULL;
           iphdr = (struct iphdr*)rbuf;
           icmphdr = (struct icmphdr*)(rbuf + (iphdr->ihl * 4));
           if (icmphdr->type == ICMP_ECHOREPLY){
                printf("ICMPTIME\n");
       		count++;
	   }
           if (count == 1)
		t1 = get_time();
           if (count == 2){
                t2 = get_time();
                printf("SUCCESS\n");
                printf("%s %f\n",entropy,t2-t1);
		close(s);
                close(t);
		exit(0);
           }
        //printf("ICMP code: %u\nICMP type: %d\n",icmphdr->code,icmphdr->type);
        }
    } 
    return 0;
}
