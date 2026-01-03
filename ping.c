#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include "ping.h"
#define TIMEOUT 10
#define PKT_SIZE 64

int main(int argc, char *argv[]){
    struct in_addr dest_ip;
    int aFlagExists = 0; //we have to make sure -a exists as it is mandatory.
    int count = 0;
    int flood = 0;
    //if parseArguments did not succeed we exit the program
    if(parseArguments(argc,argv, &dest_ip, &aFlagExists, &count, &flood) < 0) return EXIT_FAILURE;
    //ip is mandatory so we print it always 
    printf("ip is %s\n", inet_ntoa(dest_ip));
    //if we have count print it
     if(count) printf("count: %d\n",count);
    //if we have flood print it.
     if(flood) printf("flood: %d\n", flood);
     //ctrl+c activates cleanup
     signal(SIGINT, cleanup);
     
}

int parseArguments(int argc, char *argv[], struct in_addr *ip, int* aFlagExists, int* count, int* flood){
    for(int i = 0; i < argc; i++){
        if(strcmp(argv[i], "-a") == 0 && i+1 < argc){//we check both if we have -a and another field after for the ip address.
            *aFlagExists = 1;//if so we found the aFlag.
            if (inet_pton(AF_INET, argv[i+1], ip) == 1);//check if the IP is valid
            else { //if not valid we quit
                printf("invalid ip format\n");
                return -1;
            }
        }
        if(strcmp(argv[i], "-c") == 0 && i+1 < argc){
            *count = atoi(argv[i+1]);
            if (*count < 0 ||  *count > 255){
                printf("Error: count must be between 0 and 255\n");
                return -1;
            }
            if (*count == 0){
                printf("Error: -c must be an integer.\n");
                return -1;
            }
        }
        if(strcmp(argv[i], "-f") == 0 && i+1 < argc){
            *flood = atoi(argv[i+1]);
            if (*flood <= 0 ||  *flood > 255){
                printf("Error: flood must be between 0 and 255\n");
            }
            if (*flood == 0){
                printf("Error: -f must be an integer.\n");
                return -1;
            }
        }
    }
           if(!*aFlagExists){
                printf("-a flag is mandatory");
                return -1;
            }
        return 0;
}
int initSocket(){
    //creeate IPV4 Raw socket, ICMP protocol
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    //if the socket was not created successfully, we print we need sudo
    if (s < 0) {
        perror("socket");
        fprintf(stderr, "You need to be root to create raw sockets!\n");
        return -1;
    }
    struct timeval tv_out;
    //set the seconds to TIMEOUT
    tv_out.tv_sec = TIMEOUT;
    //set milliseconds to 0
    tv_out.tv_usec = 0;
    //in socketopt we add timeouts
    int success = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));
    //if set socket options is not successfull we print we need timeout 
    if (success < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(s);
        return -1;
    }
    //if all was ok we return the socket.
    return s;  
}
void * initDestStruct(struct in_addr * dest_addr){
    struct sockaddr_in dest; //create sockaddr
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;//set family to IPV4
    dest.sin_addr.s_addr = dest_addr;//set IP address to the one we got from argv.
    return &dest;
}
void start_ping_message(struct in_addr * dest_addr){
   printf("PING  (%s): %ld data bytes\n", 
           inet_ntoa((struct in_addr)*dest_addr), 
           PKT_SIZE - sizeof(struct icmphdr)); 
}
void prep_packet(char *sendBuffer, int seqNum) {
    memset(sendBuffer, 0, PKT_SIZE);
    struct icmp *icmp_pkt = (struct icmp *)sendBuffer;
    icmp_pkt->icmp_type = ICMP_ECHO;//we set header type to echo = 8 
    icmp_pkt->icmp_code = 0;//we set code to 0
    icmp_pkt->icmp_id = getpid() & 0xFFFF;//process ID number shortened to 16-bits
    icmp_pkt->icmp_seq = seqNum;//we set the packet seq number to the one from the input

    // Use a constant for the header size (8 bytes) to avoid struct confusion
    int header_len = 8; 
    
    // Fill the payload (everything after the 8-byte header)
    memset(sendBuffer + header_len, 0x42, PKT_SIZE - header_len);

    icmp_pkt->icmp_cksum = 0;// to make sure trash values do not intervene with the checksum
    icmp_pkt->icmp_cksum = in_cksum((unsigned short *)icmp_pkt, PKT_SIZE);//TODO - switch function
}



