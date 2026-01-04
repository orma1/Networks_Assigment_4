#pragma once

#include <sys/time.h>
#include <arpa/inet.h>

// Defines
#define TIMEOUT 10
#define PKT_SIZE 64

// Structs

typedef struct ring_buffer {
    struct timeval *buffer; // The actual array of timestamps
    int size;               // The max number of slots (e.g., 1024)
} RingBuffer;

typedef struct sender_args{
    char sendbuf[PKT_SIZE];
    struct sockaddr_in *dest;
    RingBuffer *ring_buffer;
    int sock;
    int count;
} SenderArgs;

typedef struct receiver_args{
    char recvbuf[PKT_SIZE + sizeof(struct ip)];
    struct sockaddr_in from;
    struct timeval tv_end;
    RingBuffer *ring_buffer;
    int sock;
    int count;
} ReceiverArgs;

// Functions declarations

int parseArguments(int argc, char *argv[], unsigned int *ip, int* aFlagExists, int* count, int* flood);
int initSocket();
void * initDestStruct(struct in_addr * dest_addr);
void start_ping_message(struct in_addr * dest_addr);
void prep_packet(char * sendBuffer, int seqNum);
int send_packet(int sockStatus, char *sendbuf, struct sockaddr_in *dest);
int receive_packet(int sockStatus, char *recvbuf, size_t bufsize, struct sockaddr_in *from);
void process_reply(char *recvbuf, int bytes, struct sockaddr_in *from, struct timeval *tv_end, RingBuffer *ring_buffer);
void cleanup(int sig);
int ping_loop(int count, int sock, struct sockaddr_in *dest);
unsigned short int calculate_checksum(void *data, unsigned int bytes);
void initialize_mutex();
void *sender_thread(void *arg);
void *receiver_thread(void *arg);
void* address_in_ringbuffer(RingBuffer *buff, int seqNum);