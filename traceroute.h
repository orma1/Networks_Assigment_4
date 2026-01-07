#define PKT_SIZE 64
#define TIMEOUT 1
#define PACKET_NUMBER 3
#define PKT_SIZE 64
#define MAX_TTL 64
#define MAX_HOPS 30
#define __POSIX_C_SOURCE 200809L
struct ip_hdr{
    uint8_t ihl:4;      // Lower 4 bits
    uint8_t version:4;  // Higher 4 bits
    uint8_t ecn:2;      // Lower 2 bits
    uint8_t dscp:6;     // Higher 6 bits
    uint16_t total_Len;
    uint16_t identification;
    uint16_t flags_FragmentOffset;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_IP_Addr;
    uint32_t dest_IP_Addr;
};


int parseArguments(int argc, char *argv[], unsigned int *dest_ip);
int initSocket();
void prep_packet(char *sendBuffer, int seqNum);
int send_packet(int sockStatus, char *sendbuf, struct sockaddr_in *dest);
int receive_packet(int sockStatus, char *recvbuf, size_t bufsize, struct sockaddr_in *from);
void process_reply(char *recvbuf, struct sockaddr_in *from, 
                   struct timeval *tv_start, struct timeval *tv_end, 
                   struct sockaddr_in *dest, int *dest_reached, struct in_addr *last_addr);
int trace_loop(int sock, struct sockaddr_in *dest);
void cleanup();
unsigned short int calculate_checksum(void *data, unsigned int bytes);
