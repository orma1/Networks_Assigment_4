#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#define TIMOUT 10
int parseArguments(int argc, char *argv[], struct in_addr *ip, int* aFlagExists, int* count, int* flood);
int main(int argc, char *argv[]){
    struct in_addr ip;
    int aFlagExists = 0; //we have to make sure -a exists as it is mandatory.
    int count = 0;
    int flood = 0;
    if(parseArguments(argc,argv, &ip, &aFlagExists, &count, &flood) < 0) return EXIT_FAILURE;
     printf("ip is %s\n", inet_ntoa(ip));
     if(count) printf("count: %d\n",count);
     if(flood) printf("flood: %d\n", flood);
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
            if (*count <= 0 ||  *count > 255){
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

