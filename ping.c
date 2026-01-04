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

int numPacketsRecieved = 0;
int numPacketsSent = 0;
int sockStatus = -1;
int main(int argc, char *argv[]){
    unsigned int dest_ip;

    int aFlagExists = 0; //we have to make sure -a exists as it is mandatory.
    int count = 0;
    int flood = 0;

    //if parseArguments did not succeed we exit the program
    if(parseArguments(argc,argv, &dest_ip, &aFlagExists, &count, &flood) < 0) return EXIT_FAILURE;
    //ip is mandatory so we print it always
    printf("ip is %s\n", inet_ntoa(*(struct in_addr *)&dest_ip));
    //if we have count print it
     if(count) printf("count: %d\n",count);
    //if we have flood print it.
     if(flood) printf("flood: %d\n", flood);
     //ctrl+c activates cleanup
     signal(SIGINT, cleanup);
    
    sockStatus = initSocket();
    if (sockStatus < 0) {
        return 1;
    }
    
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip;
    
    printf("PING %s (%s): %ld data bytes\n", 
           argv[1], 
           inet_ntoa(*(struct in_addr *)&dest_ip), 
           PKT_SIZE - sizeof(struct icmphdr));
    
    return ping_loop(count, sockStatus, &dest);

     
}

int parseArguments(int argc, char *argv[], unsigned int *ip, int* aFlagExists, int* count, int* flood){
    for(int i = 0; i < argc; i++){
        if(strcmp(argv[i], "-a") == 0 && i+1 < argc){//we check both if we have -a and another field after for the ip address.
            *aFlagExists = 1;//if so we found the aFlag.
            //check if the IP is valid
            if (inet_pton(AF_INET, argv[i+1], ip) == 1);
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
    icmp_pkt->icmp_seq = seqNum;//we set the packet seqNum number to the one from the input

    // Use a constant for the header size (8 bytes) to avoid struct confusion
    int header_len = 8; 
    
    // Fill the payload (everything after the 8-byte header)
    memset(sendBuffer + header_len, 0x42, PKT_SIZE - header_len);

    icmp_pkt->icmp_cksum = 0;// to make sure trash values do not intervene with the checksum
    icmp_pkt->icmp_cksum = calculate_checksum((unsigned short *)icmp_pkt, PKT_SIZE);//TODO - switch function
}
int send_packet(int sockStatus, char *sendbuf, struct sockaddr_in *dest) {
    //send our packet through the socket
    int bytes = sendto(sockStatus, sendbuf, PKT_SIZE, 0, 
                      (struct sockaddr *)dest, sizeof(*dest));
    //if the sendto was not successfull we print accordingly
    if (bytes < 0) {
        perror("sendto failed");
    }
    //we return the size
    return bytes;
}
int receive_packet(int sockStatus, char *recvbuf, size_t bufsize, struct sockaddr_in *from) {
    socklen_t fromlen = sizeof(*from);
    //we recieve the reply from our socket
    int bytes = recvfrom(sockStatus, recvbuf, bufsize, 0,
                        (struct sockaddr *)from, &fromlen);
    //we return the size
    return bytes;
}
void process_reply(char *recvbuf, int bytes, struct sockaddr_in *from, 
                   /*TODO-check needed fields*/ struct timeval *tv_start, struct timeval *tv_end) {
    struct ip *ip_hdr = (struct ip *)recvbuf;//IPV4 address of replier.
    int hlen = ip_hdr->ip_hl << 2;//20 bytes of IPV4 - TODO change it to hardcoded
    //initialize pointer to start of ICMP packet data relative to recvbuf.
    struct icmp *icmp_reply = (struct icmp *)(recvbuf + hlen);
    //if we got icmp_type 0 and we are the right process
    if (icmp_reply->icmp_type == ICMP_ECHOREPLY && 
        icmp_reply->icmp_id == (getpid() & 0xFFFF)) {
        numPacketsRecieved++;//for statistics.
        //we calculate RTT using start time and end time (from packets we got) 
        double rtt = (tv_end->tv_sec - tv_start->tv_sec) * 1000.0 +
                   (tv_end->tv_usec - tv_start->tv_usec) / 1000.0;
        //we print statistics about the reply packet
        printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
               bytes - hlen,//number of bytes without the header length
               inet_ntoa(from->sin_addr), //IP address of replier
               icmp_reply->icmp_seq, //seq_Num from the packet
               ip_hdr->ip_ttl, //TTL from the packet
               rtt); //RTT we calculated
    }
}
void cleanup(int sig, struct in_addr dest_addr, int sockStatus) {
    printf("\n--- %s ping statistics ---\n", inet_ntoa(*(struct in_addr *)&dest_addr));
    
    float loss = 0.0;
    if (numPacketsSent > 0)
        loss = 100.0 * (numPacketsSent - numPacketsRecieved) / numPacketsSent;
    
    printf("%d packets transmitted, %d received, %.1f%% packet loss\n",
           numPacketsSent, numPacketsRecieved, loss);
    
    if (sockStatus >= 0) 
        close(sockStatus);
    exit(0);
}
int ping_loop(int count, int sock, struct sockaddr_in *dest) {
    char sendbuf[PKT_SIZE];
    char recvbuf[PKT_SIZE + sizeof(struct ip)];
    struct sockaddr_in from;
    struct timeval tv_start, tv_end;
    int bytes;
    
    while (count - numPacketsSent) {
        prep_packet(sendbuf, numPacketsSent++);
        
        gettimeofday(&tv_start, NULL);
        
        bytes = send_packet(sock, sendbuf, dest);
        if (bytes < 0) {
            continue;
        }
        
        bytes = receive_packet(sock, recvbuf, sizeof(recvbuf), &from);
        
        gettimeofday(&tv_end, NULL);
        
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { // Same error nowdays, but in legacy Linux had diffrent value
                printf("Request timeout for icmp_seq=%d\n", numPacketsSent - 1); 
            } else {
                perror("recvfrom error");
            }
        } else {
            process_reply(recvbuf, bytes, &from, &tv_start, &tv_end);
        }
        
        sleep(1);
    }
    
    return 0;
}
/*
* @brief A checksum function that returns 16 bit checksum for data.
* @param data The data to do the checksum for.
* @param bytes The length of the data in bytes.
* @return The checksum itself as 16 bit unsigned number.
* @note This function is taken from RFC1071, can be found here:
* @note https://tools.ietf.org/html/rfc1071
* @note It is the simplest way to calculate a checksum and is not very strong.
* However, it is good enough for this assignment.
* @note You are free to use any other checksum function as well.
* You can also use this function as such without any change.
*/
unsigned short int calculate_checksum(void *data, unsigned int bytes) {
unsigned short int *data_pointer = (unsigned short int *)data;
unsigned int total_sum = 0;
// Main summing loop
while (bytes > 1) {
total_sum += *data_pointer++;
bytes -= 2;
}
// Add left-over byte, if any
if (bytes > 0)
total_sum += *((unsigned char *)data_pointer);
// Fold 32-bit sum to 16 bits
while (total_sum >> 16)
total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);
return (~((unsigned short int)total_sum));
}






