#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include "traceroute.h"

int sockStatus = -1;
struct sockaddr_in dest;
int destanationReached = 0;

int main(int argc, char *argv[]){
    unsigned int dest_ip;
    //if arguments are not ok we finish the program
    if(parseArguments(argc,argv, &dest_ip) < 0) return EXIT_FAILURE;
    sockStatus = initSocket();
    //if socket init has failed we finish the program.
    if (sockStatus < 0) return EXIT_FAILURE;
    //we set the ip to the one from the arguments and print start message.
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip;
    printf("traceroute to %s, %d hops max\n", inet_ntoa(*(struct in_addr *)&dest_ip), MAX_HOPS);
    //we call the main loop of the traceroute, with our socket and destenation ip.
    trace_loop(sockStatus, &dest);
    //after trace loop has finished we can clean the memory and close the socket
    cleanup();
    return EXIT_SUCCESS;

}
int parseArguments(int argc, char *argv[], unsigned int *dest_ip){
    int aFlagExists = 0;
    for(int i = 0; i < argc; i++){
        if(strcmp(argv[i], "-a") == 0 && i+1 < argc){//we check both if we have -a and another field after for the ip address.
            aFlagExists = 1;//if so we found the aFlag.
            //check if the IP is valid
            if (inet_pton(AF_INET, argv[i+1], dest_ip) == 1);
            else { //if not valid we quit
                printf("invalid ip format\n");
                return -1;
            }
        }
    }
    //if we have no a flag, we are missing ip parameter, so we print and quit
    if(!aFlagExists){
        printf("invalid arguments, use -a ip");
        return -1;
    }
    //if all was ok we return 0
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
    int one = 1;
    //we need to set IP_HDRINCL to tell the kernel that we are including the IP header ourselves
    success = setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if (success < 0) {
        perror("setsockopt IP_HDRINCL");
        return -1;
    }

    //if all was ok we return the socket.
    return s;  
}
void prep_packet(char *sendBuffer, int seqNum, int ttl, unsigned int dest_ip) {
    
    memset(sendBuffer, 0, PKT_SIZE);

    struct ip_hdr *ip = (struct ip_hdr *)sendBuffer;
    // The ICMP header starts immediately after the IP header (20 bytes later)
    struct icmphdr *icmp_pkt = (struct icmphdr *)(sendBuffer + sizeof(struct ip_hdr));

    //Fill IP Header
    ip->ihl = 5;        // Header length in 32-bit words (5 * 4 = 20 bytes)
    ip->version = 4;    // IPv4
    ip->ecn = 0;
    ip->dscp = 0;
    
    // Total Length = IP Header + ICMP Header + Data
    // We assume PKT_SIZE is the total size of the buffer we are sending
    ip->total_Len = htons(PKT_SIZE); 
    
    ip->identification = htons(getpid() & 0xFFFF);
    ip->flags_FragmentOffset = 0; // No special flags, offset 0
    ip->TTL = ttl;                // MUST be set here when using manual headers
    ip->protocol = IPPROTO_ICMP;
    ip->src_IP_Addr = INADDR_ANY; // Kernel will fill this automatically
    ip->dest_IP_Addr = dest_ip;   // The target IP
    ip->checksum = 0;
    ip->checksum = calculate_checksum((unsigned short *)ip, sizeof(struct ip_hdr));
    //Fill ICMP Header
    icmp_pkt->type = ICMP_ECHO;//we set header type to echo = 8 
    icmp_pkt->code = 0;//we set code to 0
    icmp_pkt->un.echo.id = getpid() & 0xFFFF;//process ID number shortened to 16-bits
    icmp_pkt->un.echo.sequence = htons(seqNum);//we set the packet seqNum number to the one from the input

    char *payload_ptr = (char *)icmp_pkt + sizeof(struct icmphdr);//start if ICMP packet payload
    
    // The length of data all - ip header - icmp header
    int payload_len = PKT_SIZE - sizeof(struct ip_hdr) - sizeof(struct icmphdr);
    
    //only fill payload if there is space
    if (payload_len > 0) {
        memset(payload_ptr, 0x42, payload_len);
    }
    icmp_pkt->checksum = 0;// to make sure trash values do not intervene with the checksum
    icmp_pkt->checksum = calculate_checksum((unsigned short *)icmp_pkt, PKT_SIZE - sizeof(struct ip_hdr));
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
void process_reply(char *recvbuf, struct sockaddr_in *from, 
                   struct timeval *tv_start, struct timeval *tv_end, 
                   struct sockaddr_in *dest, int *dest_reached, struct in_addr *last_addr) {
    // Parse Headers to check if we hit destination
    struct ip_hdr *ip = (struct ip_hdr *)recvbuf;
    int ip_header_len = ip->ihl * 4;
    struct icmphdr *icmp = (struct icmphdr *)(recvbuf + ip_header_len);
        // Calculate RTT
    double rtt = (tv_end->tv_sec - tv_start->tv_sec) * 1000.0 +
                 (tv_end->tv_usec - tv_start->tv_usec) / 1000.0;
    
    //check if type is ICMP_TIME_EXCEEDED we did not get to the target.
    if(icmp->type == ICMP_TIME_EXCEEDED){
        // if ip changed - we print it. note for the first packet in the batch, it will print always
        if(from->sin_addr.s_addr != last_addr->s_addr){
        //we force ip to be aligned with 16 chars, because it can be longer or shorter then 16 chars.
        printf("%-16s", inet_ntoa(from->sin_addr));
        *last_addr = from->sin_addr;//we update the IP because it has changed.
        //print rtt
    }
     printf("%.3f ms\t", rtt);
   }
   
    // Check if we reached the target
    // We check if it is an ECHO REPLY (Type 0) and comes from the destination IP
    // Here we also check the id - is it meant for us?
    else if (icmp->type == ICMP_ECHOREPLY && 
        from->sin_addr.s_addr == dest->sin_addr.s_addr && icmp->un.echo.id == (getpid() & 0xFFFF)) {
           if(from->sin_addr.s_addr != last_addr->s_addr){
        //we force ip to be aligned with 16 chars, because it can be longer or shorter then 16 chars.
        printf("%-16s", inet_ntoa(from->sin_addr));
        *last_addr = from->sin_addr;//we update the IP because it has changed.
        //print rtt
        }
        *dest_reached = 1;
        //print rtt
        printf("%.3f ms\t", rtt);
    }
    
}
int trace_loop(int sock, struct sockaddr_in *dest) {
    char sendbuf[PKT_SIZE];
    char recvbuf[PKT_SIZE + sizeof(struct ip_hdr)];
    struct sockaddr_in from;
    struct timeval tv_start, tv_end;
    int bytes;
    int seqNum = 0;
   //we send packet with incrementing TTL values.
    for (int ttl = 1; ttl <= MAX_HOPS; ttl++){
        //helper field to make sure we only print ip once
        struct in_addr last_addr;
        memset(&last_addr, 0, sizeof(last_addr));
        printf("%d\t", ttl);
        fflush(stdout); // for printing to appear smooth
        //send PACKET_NUMBER packets
        for (int i = 0; i < PACKET_NUMBER; i++){
            prep_packet(sendbuf, seqNum++, ttl, dest->sin_addr.s_addr);
            gettimeofday(&tv_start, NULL);
            //if the packet sending failed - we print *
            if(send_packet(sock, sendbuf, dest) < 0){
                printf("*\t");
                continue;
            }
        bytes =  receive_packet(sock, recvbuf, sizeof(recvbuf), &from);
        gettimeofday(&tv_end, NULL);
        //if we got no reply we print *
        if(bytes < 0) printf(" *");
        else{
            //if we got a packet we need to process it
            process_reply(recvbuf, &from, &tv_start, &tv_end, dest, &destanationReached, &last_addr);
        }
        fflush(stdout); // for printing to appear smooth
        }
        //after we finished printing for current row we print a new line
        printf("\n");
        //if we got to the ip we are searching, print a message and finish the loop
        if(destanationReached){
            printf("Destination reached.\n");
            break;
        }
    }
    //if we finished all the loops and still did not reach the destinations, we print accordingly
    if(!destanationReached) printf("Destination unreachable (Max hops exceeded).\n");

    //if all was sucessfull we return 0
    return 0;
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
if (bytes > 0)
total_sum += *((unsigned char *)data_pointer);
// Fold 32-bit sum to 16 bits
while (total_sum >> 16)
total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);
return (~((unsigned short int)total_sum));
}
