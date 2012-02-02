/* Tested on Linux 2.2,OpenBSD 2.6,FreeBSD 4.0 		*/ 
/* By Jonathan Leto <jonathan@leto.net>        		*/
/* October 30 2000  v0.3		       		*/
/* Thanks to ngrep.c and sniffconv.c for moral support  */

#include <pcap.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <arpa/inet.h>
#if !(__linux__)
  #include <netinet/ip_var.h>
#endif

#define ETHHDR_SIZE 14
#define PPPHDR_SIZE 4
#define SLIPHDR_SIZE 16
#define RAWHDR_SIZE 0
#define LOOPHDR_SIZE 4
#define FDDIHDR_SIZE 21
#ifndef IP_OFFMASK
	#define IP_OFFMASK 0x1fff
#endif

#define MYSQL_PORT	3306
#define TIMEOUT		5 	// seconds

int  strlenx(char *s,char d);
void prod_packet (u_char * data1, struct pcap_pkthdr *h, u_char * p);
void get_mysql_version (char *data, int len);
void errquit(char *quitmsg);
void mysql_connect(char *host);

int link_offset;
pcap_t *pd = NULL;

int main (int argc, char **argv) {

	int snaplen = 65535, promisc = 0, to = 1000 ;
	char pc_err[PCAP_ERRBUF_SIZE];
	char *filter = NULL,*dev;
	struct bpf_program pcapfilter;
	struct in_addr net, mask;

	if( argc != 2 )
		errquit("usage: ./yoursql host \n");

	filter = "tcp and src port 3306";

	if (!(dev = pcap_lookupdev(pc_err))) 
		errquit("Could not find valid device.\n");

	if ((pd = pcap_open_live (dev, snaplen, promisc, to, pc_err)) == NULL) 
		errquit("Couldn't open_live.\n");

	if (pcap_lookupnet (dev, &net.s_addr, &mask.s_addr, pc_err) == -1) {
		memset (&net, 0, sizeof (net));
    		memset (&mask, 0, sizeof (mask));
		errquit("coulnd't lookup network/netmask.\n");
	}
	if (pcap_compile (pd, &pcapfilter, filter, 0, mask.s_addr)) 
		errquit("Error in filter syntax.\n");
	
	if (pcap_setfilter (pd, &pcapfilter)) 
		errquit("pcap_setfilter error.\n");

	switch (pcap_datalink (pd)) {
		case DLT_EN10MB:
		case DLT_IEEE802:
			link_offset = ETHHDR_SIZE;
			break;

		case DLT_FDDI:
			link_offset = FDDIHDR_SIZE;
			break;

		case DLT_SLIP:
			link_offset = SLIPHDR_SIZE;
			break;

		case DLT_PPP:
			link_offset = PPPHDR_SIZE;
			break;

		case DLT_RAW:
			link_offset = RAWHDR_SIZE;
			break;

		case DLT_NULL:
			link_offset = LOOPHDR_SIZE;
			break;

		default:
    			errquit("Unsupported interface type.\n");
    			return 1;
  }
	printf("%s",argv[1]);
	mysql_connect(argv[1]);
	return 0;
}

void mysql_connect(char *host){
        int             sockfd,flags,n;
        struct sockaddr_in servaddr;
	struct hostent *hostp;
	char *connstring;

	if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		errquit("Couldn't create socket\n");

	bzero(&servaddr,sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port   = htons(MYSQL_PORT);

	hostp =  gethostbyname(host);

	memcpy(&servaddr.sin_addr,hostp->h_addr,hostp->h_length);

	flags = fcntl(sockfd,F_GETFL,0);	
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	if ( connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) 
		if( errno != EINPROGRESS ){
			printf("Got a ERROR %d error\n",errno);
			return;
		}

	/* 0x0a is the protocol version (10)
	   the last characters 5 are "test\0"
	   we don't need no steekin' API */
	connstring = "\x0a\x00\x00\x01\x85\x04\x00\x00\x80\x74\x65\x73\x74\x00\xff";

	/* version string is in second packet */
	while (pcap_loop (pd, 2, (pcap_handler) prod_packet, 0));


	if ( (n = write(sockfd,connstring,strlenx(connstring,0xff))) < 0 ){
		printf("write error %d\n",errno);	
	}

	close(sockfd);
}
int  strlenx(char *s, char d){
	int i;

	for(i=0;;i++)
		if( s[i] == d )
			break;
	return i;
}
void prod_packet (u_char * data1, struct pcap_pkthdr *h, u_char * p) {

	struct ip *ip_packet = (struct ip *) (p + link_offset);
	unsigned ip_hl = ip_packet->ip_hl * 4;
	unsigned ip_off = ntohs (ip_packet->ip_off);
	unsigned fragmented = ip_off & (IP_MF | IP_OFFMASK);
	char *data;
	int len;

	switch (ip_packet->ip_p) {
  		case IPPROTO_TCP:{
      			struct tcphdr *tcp = (struct tcphdr *) (((char *) ip_packet) + ip_hl);

			unsigned tcphdr_offset = fragmented ? 0 : (tcp->th_off * 4);

			data = ((char *) tcp) + tcphdr_offset;
      			len = ntohs (ip_packet->ip_len) - ip_hl - tcphdr_offset;
			/* our packet is small , most are 28 bytes, a few are 32 or 33 */
			if (len > 64 || len == 0)
				return;
      			get_mysql_version(data, len);
  		} break;
		default:
			errquit("Shouldn't be receiving non-tcp packets.\n");
	}
}

void errquit(char *quitmsg){
	printf("%s",quitmsg);
	exit(1);
}

void get_mysql_version (char *data, int len) {

 	char *str = data;
    	int j;

	/* the 2nd to the fifth byte will be 0x00 0x00 0x00 PROTOCOL, followed by
	the version string delimited by another null 
	Almost all recent mysql servers use protocol 10 (0x0a), but I found one that
	uses 9 (0x09)
	*/
 
	for(j=1;j<len;j++){
		if(str[j] == '\0' && str[j+1] == '\0' && str[j+2] == '\0' && (str[j+3] == 0x09 || str[j+3] == 0x0a) ){
			j+=4;
			printf(" mysql version is ");
			while( str[j] != '\0' ){
				printf("%c",str[j]);
				j++;
			}
			printf(" (protocol version %d)\n", str[4]);
		}
	}
}
