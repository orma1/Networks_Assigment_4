#include <stdlib.h>
#define PKT_SIZE 64
#define TIMEOUT 1
#define PACKET_NUMBER 3
#define PKT_SIZE 64
struct ip_hdr{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __uint8_t ihl:4;      // Lower 4 bits
    __uint8_t version:4;  // Higher 4 bits
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    __uint8_t version:4;  // Higher 4 bits
    __uint8_t ihl:4;      // Lower 4 bits
#else
    #error "Unknown Endiannes"
#endif
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
     __uint8_t ecn:2;      // Lower 2 bits
     __uint8_t dscp:6;     // Higher 6 bits
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
     __uint8_t dscp:6;
     __uint8_t ecn:2;
#endif
    __uint16_t total_Len;
    __uint16_t identification;
    __uint16_t flags_FragmentOffset;
    __uint8_t TTL;
    __uint8_t protocol;
    __uint16_t checksum;
    __uint32_t src_IP_Addr;
    __uint32_t dest_IP_Addr;
};


int parseArguments(int argc, char *argv[], unsigned int *dest_ip);
int initSocket();
void prep_packet(char *sendBuffer, int seqNum);
int send_packet(int sockStatus, char *sendbuf, struct sockaddr_in *dest);
int receive_packet(int sockStatus, char *recvbuf, size_t bufsize, struct sockaddr_in *from);
void process_reply(char *recvbuf, struct sockaddr_in *from, 
                   struct timeval *tv_start, struct timeval *tv_end, 
                   struct sockaddr_in *dest, int *dest_reached, struct in_addr *last_addr);
int ICMP_loop(int sock, struct sockaddr_in *dest);
void cleanup();
unsigned short int calculate_checksum(void *data, unsigned int bytes);
