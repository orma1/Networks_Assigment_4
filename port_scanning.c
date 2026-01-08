#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "port_scanning.h"

// -- globals --
u_int8_t isTCP;
u_int8_t isDestSet, isModeSet;
struct sockaddr_in *dest;
struct sockaddr_in *src;

int main(int argc, char *argv[]){
    int res = 0;
    res = init();
    if (res = -1){
        return EXIT_FAILURE;
    };

    res = parseArguments(argc, argv);
    if (res = -1){
        return EXIT_FAILURE;
    };


    return EXIT_SUCCESS;
}


int parseArguments(int argc, char *argv[]){
    for (int i; i < argc, i++){
        // Check whick mode we are in
        if (strcmp("-t", argv[i]) == 0 && i+1 < argc){
            if (strcmp("UDP", argv[i+1]) == 0 || strcmp("udp", argv[i+1]) == 0){
                isTCP = 0;
            };
            if (strcmp("TCP", argv[i+1]) == 0 || strcmp("tcp", argv[i+1]) == 0){
                isTCP = 1;
            };
            isModeSet = 1;
        };
        // Set IPv4 dest header
        else if (strcmp("-a", argv[i]) == 0 && i+1 < argc)
        {
            if (inet_pton(AF_INET, argv[i+1], &dest->sin_addr.s_addr ) == 1){
                isDestSet = 1;
            }
            else { //if not valid we quit
                printf("invalid ip format\n");
                return -1;
            };
        };
    };

    if (!(isDestSet && isModeSet)){
        printf("you must provide -a IPV4 destanation address with -t TYPE mode (udp or tcp)\n");
        return -1;
    }

    return 0;
}

int init(){
    
    dest = (struct sockaddr_in*)calloc(1, sizeof(struct sockaddr_in));
    if (dest == NULL) {
            printf("Dest memory allocation failed.\\n");
            return -1;
    }
    src = (struct sockaddr_in*)calloc(1, sizeof(struct sockaddr_in));
    if (src == NULL) {
            printf("Src memory allocation failed.\\n");
            return -1; 
    }

    if (inet_pton(AF_INET, "127.0.0.1", &src->sin_addr.s_addr ) != 1){
        printf("Failed to set up source IP during init\n");
        return -1;
    }

    return 0;
}

struct sockaddr_in* get_local_ip(){
    // Setting a DNS target (8.8.8.8).
    struct sockaddr_in DNS_dummy_target;
    DNS_dummy_target.sin_family = AF_INET; 
    DNS_dummy_target.sin_port = htons(53); // Transform from little endian to big endian.
    if (inet_pton(AF_INET, "8.8.8.8", &DNS_dummy_target.sin_addr ) != 1){
        printf("Failed to set up DNS IP for UDP during init\n");
        return -1;
    }

    // Open the socket 
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        printf("Failed to create a socket");
        return -1;
    }

    // Send a packet
    // ssize_t sendto(int socket, const void *message, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
    int bytes = sendto(s, NULL, 0, 0, DNS_dummy_target, sizeof(DNS_dummy_target));
    if (bytes < 0){
        printf("Failed to create send a message to DNS Dummy");
        return -1;
    }

    return NULL;
}