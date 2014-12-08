
#include <signal.h>
#include <stdio.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <stdlib.h>
#include <errno.h> 
#include <netinet/udp.h>   
#include <netinet/ip.h> 
#include <netinet/ip_icmp.h>
#include <unistd.h> 
#include <sys/time.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#define RANDPATH "/dev/urandom"

/* used to get the Source IP*/
int countChars( char* s, char c ) 
{
    return *s == '\0'
              ? 0
              : countChars( s + 1, c ) + (*s == c);
}

/*  Just returns current time as double, with most possible precision...  */
double get_time (void) {
	struct timeval tv;
	double d;
	gettimeofday (&tv, NULL);
	d = ((double) tv.tv_usec) / 1000000. + (unsigned long) tv.tv_sec;
	return d;
}

/* used to calculate checksum */
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
 
    struct ifaddrs *myaddrs, *ifa;
    void *in_addr;
    char source_ip[64];

    if(getifaddrs(&myaddrs) != 0)
    {
        perror("getifaddrs");
        exit(1);
    }

    //for loop used to get correct source IP
    for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        switch (ifa->ifa_addr->sa_family)
        {
            case AF_INET:
            {
                struct sockaddr_in *s4 = (struct sockaddr_in *)ifa->ifa_addr;
                in_addr = &s4->sin_addr;
                break;
            }

            case AF_INET6:
            {
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                in_addr = &s6->sin6_addr;
                break;
            }

            default:
                continue;
        }

        if (!inet_ntop(ifa->ifa_addr->sa_family, in_addr, source_ip, sizeof(source_ip)))
        {
            printf("%s: inet_ntop failed!\n", ifa->ifa_name);
        }
        else
        {
            int c = countChars(source_ip,'.'); //used to make sure it is IPv4 and not loopback
            if (strncmp(source_ip,"127",3) != 0  && c == 3)
            	break;
        }
    }
    freeifaddrs(myaddrs);
    printf("Source IP: %s\n", source_ip);
   
    unsigned int rand;
    FILE *f;  //used for urandom
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

    //Raw socket for UDP packets
    int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
     
    if(s == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create raw socket");
        exit(1);
    }

    //RAW socket for ICMP packets
    int t = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if(t == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create receive raw socket");
        exit(1);
    }

    struct iphdr *iph; 
    struct udphdr *udph;   
    int new_size =  load_size + 1;
    char datagram[4096], word[new_size], *data;
    memset (datagram, 0, 4096);
    memset (word, 0, new_size);
    
    //IP header
    iph = (struct iphdr *) datagram;

    //ICMP
    struct icmphdr* icmphdr = NULL;
    char buf[sizeof(struct icmp)]; 
    char rbuf[sizeof(struct iphdr) + sizeof(struct icmp)];  

    //UDP header
    udph = (struct udphdr *) (datagram + sizeof (struct iphdr));
     
    struct sockaddr_in sin, addr;
       
    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);

    //fill the data part whether it is high or low entropy
    if (strcmp(entropy,"H") == 0)
    {
	f = fopen(RANDPATH, "r");
        for (i = 0; i < load_size; i++){
            fread(&rand,sizeof(rand),1,f);
            int temp = (int)rand%2;
            if (temp == 0)
    	    	word[i] = '0';
	    else
		word[i] = '1';
        }
        fclose(f);
    }
    else if (strcmp(entropy,"L") == 0)
    {
    	for (i = 0; i < load_size; i++){
            word[i] = '0';
        }
    }

    word[load_size] = '\0';
    strcpy(data , word);
     
    sin.sin_family = AF_INET;
    sin.sin_port = dest_port;
    sin.sin_addr.s_addr = inet_addr (dest_IP);
     
    //IP header being filled
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    iph->id = htons (5000);
    iph->frag_off = 0;
    iph->ttl = ttl;
    iph->protocol = 17; //IPPROTO_UDP
    iph->check = 0;   //Initially set to 0
    iph->saddr = inet_addr (source_ip); 
    iph->daddr = inet_addr (dest_IP);
     
    //Ip checksum
    iph->check = ip_checksum ((unsigned short *) iph, sizeof(struct iphdr));
     
    //UDP header
    udph->source = htons (6666);
    udph->dest = htons (dest_port);
    udph->len = htons(8 + strlen(data));
    udph->check = 0;
    
    //create icmp message
    icmphdr = (struct icmphdr*)buf;
    memset(icmphdr, 0, sizeof(struct icmphdr));
    icmphdr->type = ICMP_ECHO;
    icmphdr->un.echo.sequence = 50;
    icmphdr->un.echo.id = 48;
    icmphdr->checksum = ip_checksum((unsigned short*)icmphdr, sizeof(struct icmphdr));
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_aton(dest_IP, &addr.sin_addr);
     
    pid_t pid = fork(); // 2 processes
    if (pid == 0)  //sender + child process
    {
        prctl(PR_SET_PDEATHSIG, SIGHUP); //kill this process when parent exits
        //send head ICMP packet
	printf("Sending Head ICMP packet\n");
        sendto(t, buf, sizeof(struct icmphdr), 0, (struct sockaddr*)&addr, sizeof(addr));
	sleep(1);
	for(i = 0; i < load_num; i++){   //send UDP train
           if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
           {
              perror("sendto failed");
           }
           //Data send successfully
           else
           {
              printf ("Packet Sent. Num: %d\n" , i+1);
           }
        }
        for (i = 0; i < icmp_num; i++){
           //Send tail ICMP packets
           sendto(t, buf, sizeof(struct icmphdr), 0, (struct sockaddr*)&addr, sizeof(addr));
           printf("Sent Num %d ICMP tail packet of %d\n",i+1,icmp_num);
           printf("Entering Sleep Time of %d seconds\n",sleep_time);
	   sleep(sleep_time);
        }
        close(s);
    }
    else  //receiver + parent process
    {
        int count = 0;
	while(1){
           rc = recvfrom(t, rbuf, sizeof(rbuf) ,  0, (struct sockaddr *)&raddr, &raddr_len); 
           struct iphdr* iphdr = NULL;
           struct icmphdr* icmphdr = NULL;
           iphdr = (struct iphdr*)rbuf;
           icmphdr = (struct icmphdr*)(rbuf + (iphdr->ihl * 4));
           if (icmphdr->type == ICMP_ECHOREPLY){
       		count++;  //increment count when ICMP reply received
	   }
           if (count == 1 && icmphdr->type == ICMP_ECHOREPLY){
		t1 = get_time();
                printf("First ICMP reply received\n");
	   }
           if (count == 2){
                t2 = get_time();
                printf("Second ICMP reply received\n");
		double s = t2-t1;
                printf("%s %f\n",entropy,s);
		close(s);
                close(t);
		exit(0);
           }
        }
    } 
    return 0;
}
