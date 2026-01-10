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
#include <math.h>
#include "ping.h"


pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; // Mutex for thread safety

int numPacketsRecieved = 0;
int numPacketsSent = 0;
int sockStatus = -1;
int floodMode = 0; // TODO: make -f just a flag witout args
struct sockaddr_in dest;
RingBuffer ring_buffer;

// For stats
double min_rtt = 9999.0;
double max_rtt = 0.0;
double sum_rtt = 0.0;
double sum_sq_rtt = 0.0; // Sum of squares for mdev


int main(int argc, char *argv[]){
    int aFlagExists = 0; //we have to make sure -a exists as it is mandatory.
    int count = 0;
    unsigned int dest_ip;

    struct timeval *b = (struct timeval *)calloc(1024, sizeof(struct timeval));
    if (!b){
        printf("failed to set buffer ring dynamic memory");
        return EXIT_FAILURE;
    }
    ring_buffer.buffer = b;
    ring_buffer.size = 1024;

    //if parseArguments did not succeed we exit the program
    if(parseArguments(argc,argv, &dest_ip, &aFlagExists, &count) < 0) {
        cleanup();
        return EXIT_FAILURE;
    }

    //ctrl+c activates cleanup
    signal(SIGINT, cleanup);
    
    sockStatus = initSocket();
    if (sockStatus < 0) {
        cleanup();
        return EXIT_FAILURE;
    }
    
    // init dest
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip;
    
    start_ping_message(&dest.sin_addr.s_addr, count);

    // Thread sender args
    SenderArgs sender_args = {
        .dest = &dest,
        .ring_buffer = &ring_buffer,
        .sock = sockStatus,
        .count = count
    };

    // Thread receiver args
    ReceiverArgs receiver_args = {
        .ring_buffer = &ring_buffer,
        .sock = sockStatus,
        .count = count
    };

    pthread_t senderT, receiverT;

    // Create the threads
    pthread_create(&senderT, NULL, sender_thread, &sender_args);
    pthread_create(&receiverT, NULL, receiver_thread, &receiver_args);

    // Wait for them to finish
    pthread_join(senderT, NULL);
    pthread_join(receiverT, NULL);

    // We are done
    cleanup();

    return EXIT_SUCCESS;
}

int parseArguments(int argc, char *argv[], unsigned int *ip, int* aFlagExists, int* count){
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
                printf("Error: -c must be an integer (in range of 1 to 255).\n");
                return -1;
            }
        }
        if(strcmp(argv[i], "-f") == 0){    
            floodMode = 1;
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


void start_ping_message(struct in_addr *dest_addr, int count){
    char *message; 
    if (floodMode){
        message = "Activated";
    }else {
        message = "Deactivated";
    }

    printf("\n=============================================================\n");
    printf("   PING SESSION: %s\n", inet_ntoa((struct in_addr)*dest_addr));
    printf("   PACKET SIZE:  %ld bytes\n", PKT_SIZE - sizeof(struct icmphdr));
    printf("   Flags: -f: %s, -c: %d \n", message, count);
    printf("=============================================================\n");
}

// Thread Function
void prep_packet(char *sendBuffer, int seqNum) {
    memset(sendBuffer, 0, PKT_SIZE);
    struct icmp *icmp_pkt = (struct icmp *)sendBuffer;
    icmp_pkt->icmp_type = ICMP_ECHO;//we set header type to echo = 8 
    icmp_pkt->icmp_code = 0;//we set code to 0
    icmp_pkt->icmp_id = getpid() & 0xFFFF;//process ID number shortened to 16-bits
    icmp_pkt->icmp_seq = htons(seqNum);//we set the packet seqNum number to the one from the input

    // Use a constant for the header size (8 bytes) to avoid struct confusion
    int header_len = 8; 
    
    // Fill the payload (everything after the 8-byte header)
    memset(sendBuffer + header_len, 0x42, PKT_SIZE - header_len);

    icmp_pkt->icmp_cksum = 0;
    icmp_pkt->icmp_cksum = calculate_checksum((unsigned short *)icmp_pkt, PKT_SIZE);
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

// Thread Function
int receive_packet(int sockStatus, char *recvbuf, size_t bufsize, struct sockaddr_in *from) {
    socklen_t fromlen = sizeof(*from);
    //we recieve the reply from our socket
    int bytes = recvfrom(sockStatus, recvbuf, bufsize, 0,
                        (struct sockaddr *)from, &fromlen);
    //we return the size
    return bytes;
}

// Thread Function
void process_reply(char *recvbuf, int bytes, struct sockaddr_in *from, struct timeval *tv_end, RingBuffer *ring_buffer) {
    struct ip *ip_hdr = (struct ip *)recvbuf;// IPV4 address of replier.
    int hlen = ip_hdr->ip_hl << 2;// 20 bytes of IPV4 
    // pointer to the start of ICMP packet data relative to recvbuf.
    struct icmp *icmp_reply = (struct icmp *)(recvbuf + hlen);
    //if we got icmp_type 0 and we are the right process
    if (icmp_reply->icmp_type == ICMP_ECHOREPLY && 
        icmp_reply->icmp_id == (getpid() & 0xFFFF)) {
        int seqNum = ntohs(icmp_reply->icmp_seq); // From big endian to little
        struct timeval *tv_start = address_in_ringbuffer(ring_buffer, seqNum);
        numPacketsRecieved++;//for statistics.
        //we calculate RTT using start time and end time (from packets we got) 
        double rtt = (tv_end->tv_sec - tv_start->tv_sec) * 1000.0 +
                   (tv_end->tv_usec - tv_start->tv_usec) / 1000.0;
        // Update statistics
        if (max_rtt < rtt){
            max_rtt = rtt;
        }
        if (min_rtt > rtt){
            min_rtt = rtt;
        }
        sum_rtt += rtt;
        sum_sq_rtt += (rtt * rtt);
        printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
               bytes - hlen,//number of bytes without the header length
               inet_ntoa(from->sin_addr), //IP address of replier
               seqNum, //seq_Num from the packet
               ip_hdr->ip_ttl, //TTL from the packet
               rtt
            ); 
    }
}

void cleanup() {
    printf("\n=============================================================\n");
    printf("--- %s ping statistics ---\n", inet_ntoa(dest.sin_addr));
    
    float loss = 0.0;
    if (numPacketsSent > 0)
        loss = 100.0 * (numPacketsSent - numPacketsRecieved) / numPacketsSent;
    
    printf("%d packets transmitted, %d received, %.1f%% packet loss\nrtt min/avg/max/mdev = %.2f/%.2f/%.2f/%.2f \n",
            numPacketsSent, 
            numPacketsRecieved, 
            loss,
            min_rtt,
            sum_rtt/numPacketsRecieved,
            max_rtt,
            sqrt((sum_sq_rtt/numPacketsRecieved) - (sum_rtt/numPacketsRecieved)*(sum_rtt/numPacketsRecieved))
        );

    printf("=============================================================\n");
    if (sockStatus >= 0) 
        close(sockStatus);

    free(ring_buffer.buffer);

    pthread_mutex_destroy(&lock);
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

void* address_in_ringbuffer(RingBuffer *buff, int seqNum) {
    return &buff->buffer[seqNum % buff->size];
}


void *sender_thread(void *arg) {
    // Cast the argument to the correct type
    struct sender_args *args = (struct sender_args *)arg;
    int bytes;
    while(args->count == 0 || numPacketsSent < args->count) {
        pthread_mutex_lock(&lock);
        prep_packet(args->sendbuf, numPacketsSent);
        gettimeofday(address_in_ringbuffer(args->ring_buffer ,numPacketsSent), NULL);
        numPacketsSent++;
        
        pthread_mutex_unlock(&lock);

        bytes = send_packet(args->sock, args->sendbuf, args->dest);
        if (bytes < 0) {
            // if failed to send it's a packet loss
            printf("Error: failed to send a packet\n");
            perror("ping: sendto");
        }

        if (!floodMode){
            sleep(1);
        }
    }
    // Implementation of sender thread
    return NULL;
}


void *receiver_thread(void *arg) {
    struct receiver_args *args = (struct receiver_args *)arg;

    while (args->count == 0 || numPacketsRecieved < args->count){
        int bytes = receive_packet(args->sock, args->recvbuf, sizeof(args->recvbuf), &args->from);

        gettimeofday(&args->tv_end, NULL);

        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { // Same error nowdays, but in legacy Linux had diffrent value
                printf("Request timeout for icmp_seq=%d\n", numPacketsSent - 1); 
            } else {
                perror("recvfrom error");
            }
        } else {
            process_reply(args->recvbuf, bytes, &args->from, &args->tv_end, args->ring_buffer);
        }
    }

    return NULL;
}