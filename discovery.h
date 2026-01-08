#define TIMEOUT 1
#define PKT_SIZE 64
int parseArguments(int argc, char *argv[], unsigned int *ip, int *c);
int initSocket();
void prep_packet(char *sendBuffer, int seqNum);
int send_packet(int sockStatus, char *sendbuf, struct sockaddr_in *dest);
int receive_packet(int sockStatus, char *recvbuf, size_t bufsize, struct sockaddr_in *from);
void ipDiscoveryLoop(int c);
void cleanup();
unsigned short int calculate_checksum(void *data, unsigned int bytes);