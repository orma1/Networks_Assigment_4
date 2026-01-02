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

int main(int argc, char *argv[]){
    struct in_addr ip;
    int aFlagExists = 0; //we have to make sure -a exists as it is mandatory.
    int count = 0;
    int back_to_back = 0;
   for(int i = 0; i < argc; i++){
        if(strcmp(argv[i], "-a") == 0 && i+1 < argc){//we check both if we have -a and another field after for the ip address.
            aFlagExists = 1;//if so we found the aFlag.
            if (inet_pton(AF_INET, argv[i+1], &ip) == 1) printf("ip is %s\n", inet_ntoa(ip));//check if the IP is valid an if so print it
            else { //if not valid we quit
                printf("invalid ip format\n");
                return EXIT_FAILURE;
            }
        }
        if(strcmp(argv[i], "-c") == 0 && i+1 < argc){
            count = argv[i+1];
        }
        if(strcmp(argv[i], "-f") == 0 && i+1 < argc){
            back_to_back = argv[i+1];
        }
    }
   if(!aFlagExists){
    printf("-a flag is mandatory");
    return EXIT_FAILURE;
   }
}
