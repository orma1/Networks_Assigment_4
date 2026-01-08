#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include "discovery.h"
int sockStatus = -1;
struct sockaddr_in dest;

int main(int argc, char *argv[]){
    unsigned int dest_ip;
    int c;
    //if arguments are not ok we finish the program
    if(parseArguments(argc,argv, &dest_ip, &c) < 0) return EXIT_FAILURE;
    sockStatus = initSocket();
    //if socket init has failed we finish the program.
    if (sockStatus < 0) return EXIT_FAILURE;
    //we set the ip to the one from the arguments and print start message.
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip;
    ipDiscoveryLoop(c);
    cleanup();
    return 0;
}
int parseArguments(int argc, char *argv[], unsigned int *ip, int *c){
    int aFlagExists = 0;
    int cFlagExists = 0;
    for(int i = 0; i < argc; i++){
        if(strcmp(argv[i], "-a") == 0 && i+1 < argc){//we check both if we have -a and another field after for the ip address.
            aFlagExists = 1;//if so we found -a
            //check if the IP is valid
            if (inet_pton(AF_INET, argv[i+1], ip) == 1);
            else { //if not valid we quit
                printf("invalid ip format\n");
                return -1;
            }
        }
        if(strcmp(argv[i], "-c") == 0 && i+1 < argc){
            cFlagExists = 1; //if so we found -c
            *c = atoi(argv[i+1]);
            if (*c < 0 ||  *c > 32){
                printf("Error: count must be between 0 and 32\n");
                return -1;
            }
            if (*c == 0){
                printf("Error: -c must be an integer.\n");
                return -1;
            }
        }
    }
           if(!aFlagExists){
                printf("-a flag is mandatory");
                return -1;
            }
             if(!cFlagExists){
                printf("-c flag is mandatory");
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
    return s;
}
void prep_packet(char *sendBuffer, int seqNum) {
    //TODO - make ip hdr manual.
    memset(sendBuffer, 0, PKT_SIZE);
    struct icmphdr *icmp_pkt = (struct icmphdr *)sendBuffer;
    icmp_pkt->type = ICMP_ECHO;//we set header type to echo = 8 
    icmp_pkt->code = 0;//we set code to 0
    icmp_pkt->un.echo.id = htons(getpid() & 0xFFFF);//process ID number shortened to 16-bits
    icmp_pkt->un.echo.sequence = htons(seqNum);//we set the packet seqNum number to the one from the input

    // Use a constant for the header size (8 bytes) to avoid struct confusion
    int header_len = 8; 
    
    // Fill the payload (everything after the 8-byte header)
    memset(sendBuffer + header_len, 0x42, PKT_SIZE - header_len);

    icmp_pkt->checksum = 0;// to make sure trash values do not intervene with the checksum
    icmp_pkt->checksum = calculate_checksum((unsigned short *)icmp_pkt, PKT_SIZE);//TODO - switch function
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

void ipDiscoveryLoop(int c){
    uint32_t mask = 0xFFFFFFFF << (32-c);
    long numberOfhosts = pow(2,(32-c));
    uint32_t ip = ntohl(dest.sin_addr.s_addr);
    struct sockaddr_in from;
    int seqNum = 0;
    uint32_t startIp = ip & mask;//we do not start from given ip, we start from the start of the subnet.
    char sendbuf[PKT_SIZE];
    char recvbuf[PKT_SIZE + sizeof(struct iphdr)];
    int bytes;
    //we skip 0 and 255 as they are reserved
    printf("scanning %s/%d\n",inet_ntoa(dest.sin_addr),c);
    for (unsigned int i = startIp; i <= startIp + numberOfhosts - 1; i++)
    {
        // SKIP the first address (Network Address) and last address (Broadcast Address)
        //trying last address can result in error
        //because linux does not allow to send packets to broadcast without SO_BROADCAST flag
        if (i == startIp || i == startIp + numberOfhosts - 1) continue;
        dest.sin_addr.s_addr = htonl(i);
        prep_packet(sendbuf, seqNum);
        
        bytes = send_packet(sockStatus, sendbuf, &dest);
        if (bytes < 0) {
            continue;
        }
        
        bytes = receive_packet(sockStatus, recvbuf, sizeof(recvbuf), &from);
        if (bytes >0) {
            //parse the headers
            struct iphdr *ip_header = (struct iphdr *)recvbuf;
            int ip_header_len = ip_header->ihl * 4;
            struct icmphdr *icmp_reply = (struct icmphdr *)(recvbuf + ip_header_len);

            //check if Echo Reply and if this packet is for out program
            if (icmp_reply->type == ICMP_ECHOREPLY && ntohs(icmp_reply->un.echo.id) == (getpid() & 0xFFFF)) {
                    //check sequence numbers to make sure it is not delayed packet and increment for next iteration
                    if (ntohs(icmp_reply->un.echo.sequence) == seqNum) {
                        printf("%s\n", inet_ntoa(from.sin_addr));
                    }
                }
            }
        seqNum++; //reply or no reply we increment
    } 
    printf("Scan Complete!\n");
}
    
void cleanup() {
    //if the socket was opened, we close it
    if (sockStatus >= 0) close(sockStatus);
    exit(0);
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
    if (bytes > 0) total_sum += *((unsigned char *)data_pointer);

    // Fold 32-bit sum to 16 bits
    while (total_sum >> 16) total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);

    return (~((unsigned short int)total_sum));
}
