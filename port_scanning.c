#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "port_scanning.h"

// -- globals --
u_int8_t isTCP;
u_int8_t isDestSet, isModeSet;
struct sockaddr_in *dest;
struct sockaddr_in *src;
Psuedo_Header *psuedo_header;
struct tcphdr *tcp_header;
struct udphdr *udp_header;
u_int16_t curr_port;
u_int16_t our_port;
u_int32_t seqNum;

// -- ICMP_SOCK --
int ICMP_SOCK;
int dummy_sock = -1;

int main(int argc, char *argv[]){
    int res = 0;
    res = init();
    if (res == -1){
        cleanup(NULL);
        return EXIT_FAILURE;
    };

    res = parseArguments(argc, argv);
    if (res == -1){
        cleanup(NULL);
        return EXIT_FAILURE;
    };

    int sock = initSocket();
    if (sock == -1){
        cleanup(NULL);
        return EXIT_FAILURE;
    }

    // init tmp storage
    LinkedList *open_ports = NULL;
    int bytes = 0;
    socklen_t addr_len = sizeof(*dest);

    unsigned char tcp_packet_response[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(tcp_packet_response,0,sizeof(tcp_packet_response));
    
    unsigned char udp_packet_response[1024]; // <-- reply may be big
    memset(udp_packet_response,0,1024);

    unsigned char icmp_packet_response[64]; // <-- 64 bytes (Enough to hold Outer IP + ICMP + Inner IP + Inner UDP)
    memset(icmp_packet_response,0,sizeof(icmp_packet_response));

    // Sending Loop
    while (curr_port < START_RANGE + MAX_PORTS && curr_port < MAX_RANGE){
        if (isTCP){
            // prepare the packet
            prepare_packet(TH_SYN);
            // send packet
            sendto(sock, tcp_header, sizeof(*tcp_header), 0, dest, sizeof(*dest));
            printf("Sent a check to port num %d \n", curr_port);
                // Wait for our response
                while (1) {
                    bytes = recvfrom(sock, tcp_packet_response, sizeof(tcp_packet_response), 0, (struct sockaddr *)dest, &addr_len);
                    if (bytes < 0) {
                        printf("Timeout for port num %d \n", curr_port);
                        // timeout was reached with no matching packet
                        break; 
                    }

                    struct tcphdr *tcp_resp = (struct tcphdr *)(tcp_packet_response + sizeof(struct iphdr));
                    // FILTER: Check if this packet is actually the reply to our scan
                    if (ntohs(tcp_resp->th_dport) == our_port && ntohs(tcp_resp->th_sport) == curr_port) {
                        
                        printf("Recieved an answer from port num %d \n", curr_port);
                        // check the flags.
                        if ((tcp_resp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
                            open_ports = add_port(open_ports, curr_port);
                            printf("Found an open port, port num %d \n", curr_port);
                            // Send the RST to close the connection properly
                            seqNum++; 
                            prepare_packet(TH_RST);
                            sendto(sock, tcp_header, sizeof(*tcp_header), 0, (struct sockaddr *)dest, sizeof(*dest));
                            seqNum = rand();
                        }
                        break; 
                    }
                }
            // check next port
            curr_port++;
        }else{
            // prepare the packet
            prepare_packet(0);
            // send packet
            sendto(sock, udp_header, sizeof(*udp_header), 0, dest, sizeof(*dest));
            printf("Sent a check to port num %d \n", curr_port);
            while(1) {
                fd_set listener;
                struct timeval timeout;
                
                FD_ZERO(&listener);
                FD_SET(sock, &listener);
                FD_SET(ICMP_SOCK, &listener);

                if (dummy_sock != -1) {
                    FD_SET(dummy_sock, &listener);
                }
                
                timeout.tv_sec = TIMEOUT;
                timeout.tv_usec = 0;

                int max = sock;
                if (ICMP_SOCK > max) max = ICMP_SOCK;
                if (dummy_sock > max) max = dummy_sock;

                int resp = select(max + 1, &listener, NULL, NULL, &timeout);

                if (resp == 0) {
                    printf("Timeout occurred for port: %d\n", curr_port);
                    curr_port++; 
                    break;      
                } 
                else {
                    // Check dummy Socket
                    if (dummy_sock != -1 && FD_ISSET(dummy_sock, &listener)) {
                        struct sockaddr_in reply_addr;
                        socklen_t reply_len = sizeof(reply_addr);
                        char junk[1024];

                        // 1. Capture the sender's address so we know WHICH port replied
                        int bytes = recvfrom(dummy_sock, junk, sizeof(junk), 0, (struct sockaddr *)&reply_addr, &reply_len);
                        
                        if (bytes >= 0) {
                            // 2. Extract the actual port from the sender
                            int actual_port = ntohs(reply_addr.sin_port);
                            
                            // 3. Add to open ports list (even if it's a late packet)
                            open_ports = add_port(open_ports, actual_port);

                            // 4. Logic: Did we get the answer for the CURRENT port?
                            if (actual_port == curr_port) {
                                printf("Found an open port: %d (via reply)\n", curr_port);
                                curr_port++;
                                seqNum = rand();
                                break; // EXIT the inner loop to scan the next port
                            } 
                            else {
                                // This was a "Late Packet" from a previous timeout.
                                // We recorded it above, but we DO NOT break.
                                // We keep waiting for the CURRENT curr_port to reply or timeout.
                                printf("Debug: Received late reply for port %d while scanning %d\n", actual_port, curr_port);
                            }
                        }
                    }
                    // Check UDP Socket
                    if (FD_ISSET(sock, &listener)) {
                        bytes = recvfrom(sock, udp_packet_response, sizeof(udp_packet_response), 0, (struct sockaddr *)dest, &addr_len);
                        // Validate packet length to avoid crashes on small junk packets
                        if (bytes >= sizeof(struct iphdr) + sizeof(struct udphdr)) {
                            struct udphdr *ptr = (struct udphdr *)&udp_packet_response[sizeof(struct iphdr)];
                            
                            if (ntohs(ptr->uh_sport) == curr_port) {
                                // MATCH! Open Port.
                                add_port(open_ports, curr_port);
                                curr_port++; // Move to next port
                                seqNum = rand();
                                break;       // Exit inner loop
                            }
                        }
                    }
                    
                    // Check ICMP Socket
                    if (FD_ISSET(ICMP_SOCK, &listener)) {
                        bytes = recvfrom(ICMP_SOCK, icmp_packet_response, sizeof(icmp_packet_response), 0, (struct sockaddr *)dest, &addr_len);
                        
                        // We need at least 56 bytes (IP + ICMP + Inner IP + Inner UDP)
                        if (bytes >= 56) {
                            struct icmphdr *ptr = (struct icmphdr *)&icmp_packet_response[sizeof(struct iphdr)];
                            
                            if (ptr->type == ICMP_DEST_UNREACH && ptr->code == ICMP_PORT_UNREACH) {
                                // 1. Jump over ICMP Header (8 bytes) to get Inner IP
                                struct iphdr *inner_ip = (struct iphdr *)((char *)ptr + 8);
                                
                                // 2. Jump over Inner IP Header to get Inner UDP
                                int inner_ip_len = inner_ip->ihl * 4;
                                struct udphdr *inner_udp = (struct udphdr *)((char *)inner_ip + inner_ip_len);
                                
                                // KEEP ONLY FOR DEBUG. 
                                // int failed_port = ntohs(inner_udp->uh_dport);
                                // printf("\n[DEBUG] ICMP Error Received! Failed Port: %d | Current Scan: %d\n", failed_port, curr_port);

                                // 3. ONLY fail if the error is for the CURRENT port
                                if (ntohs(inner_udp->uh_dport) == curr_port) {
                                    printf("Port is closed: %d\n", curr_port);
                                    curr_port++; 
                                    seqNum = rand();
                                    break; 
                                }
                            }
                        }
                    }
                }
            }
        }
        
    }


    print_scan_results(open_ports);
    cleanup(open_ports);

    return EXIT_SUCCESS;
}


int parseArguments(int argc, char *argv[]){
    for (int i = 0; i < argc; i++){
        // Check whick mode we are in
        if (strcmp("-t", argv[i]) == 0 && i+1 < argc){
            if (strcmp("UDP", argv[i+1]) == 0 || strcmp("udp", argv[i+1]) == 0){
                isTCP = 0;
            };
            if (strcmp("TCP", argv[i+1]) == 0 || strcmp("tcp", argv[i+1]) == 0){
                isTCP = 1;
            };
            isModeSet = 1;

        } else if (strcmp("-a", argv[i]) == 0 && i+1 < argc)  // Set IPv4 dest header
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

    // find src local IP
    uint32_t local_ip = get_local_ip();
    if (local_ip == 0) {
        printf("Could not determine local IP\n");
        return -1;
    }
    src->sin_addr.s_addr = local_ip;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_ip, ip_str, INET_ADDRSTRLEN);
    printf("Scanner initialized on local IP: %s\n", ip_str);

    // Init the psuedo_header
    psuedo_header = calloc(1, sizeof(Psuedo_Header));
    if (psuedo_header == NULL){
        printf("Psuedo header faild to INIT");
        return -1;
    }

    // init TCP header    
    tcp_header = (struct tcphdr *)calloc( 1,sizeof(struct tcphdr));
    if (tcp_header == NULL){
        printf("TCP header faild to INIT");
        return -1;
    }
    udp_header = (struct udphdr*)calloc(1, sizeof(struct udphdr));
    if (udp_header == NULL){
        printf("UDP header faild to INIT");
        return -1;
    }
    // init dest port
    curr_port = START_RANGE;
    // init our src port
    our_port = 5555;
    seqNum = rand();

    // Setup Dummy Socket so the OS reserve Port 5555
    if (!isTCP) {
        dummy_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (dummy_sock < 0) {
            perror("Dummy socket creation failed");
            return -1;
        }

        struct sockaddr_in dummy_addr;
        memset(&dummy_addr, 0, sizeof(dummy_addr));
        dummy_addr.sin_family = AF_INET;
        dummy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        dummy_addr.sin_port = htons(our_port); // Bind to 5555

        if (bind(dummy_sock, (struct sockaddr *)&dummy_addr, sizeof(dummy_addr)) < 0) {
            perror("Dummy socket bind failed");
            // It might fail if you run the scanner twice quickly. 
            // You can try changing 'our_port' or just ignore this if testing.
            return -1;
        }
    }

    return 0;
}

unsigned int calculate_sum(void *data, unsigned int bytes) {
    unsigned short int *data_pointer = (unsigned short int *)data;
    unsigned int total_sum = 0;
    // Main summing loop
    while (bytes > 1) {
        total_sum += *data_pointer++;
        bytes -= 2;
    }
    // Add left-over byte, if any
    if (bytes > 0) total_sum += *((unsigned char *)data_pointer);
    return (((unsigned int)total_sum));
}


unsigned short int checksum(Psuedo_Header *ps, void *protocl_h){
    unsigned int sum = 0;

    sum += calculate_sum(ps, sizeof(Psuedo_Header));

    if (isTCP){
        struct tcphdr *tcp_h = (struct tcphdr *) protocl_h;
        sum += calculate_sum(tcp_h, sizeof(struct tcphdr));
    }else{
        struct udphdr *udp_h = (struct udphdr *) protocl_h;
        sum += calculate_sum(udp_h, sizeof(struct udphdr));
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

    return (~((unsigned short int)sum));
}

void prepare_packet(uint8_t flag){

    psuedo_header->src = src->sin_addr.s_addr;
    psuedo_header->dest = dest->sin_addr.s_addr;
    if (isTCP) {
        psuedo_header->protocol = 6;
        psuedo_header->segment_length = htons(20);
    }else {
        psuedo_header->protocol = 17;
        psuedo_header->segment_length = htons(8);
    }


    if (isTCP){
        // set ports
        tcp_header->th_sport = htons(our_port);
        tcp_header->th_dport =  htons(curr_port);
        // seq starting number
        tcp_header->th_seq = htonl(seqNum);
        tcp_header->th_ack = 0;
        // Data Offset: 5 words * 4 bytes = 20 bytes <-- minimun TCP header size when payload is empty
        tcp_header->th_off = 5;
        // Sending a SYN
        tcp_header->th_flags = flag;
        // Window Size
        tcp_header->th_win = htons(65535);
        // Checksum has to be 0 before calculation
        tcp_header->th_sum = 0;
        // Urgent pointer
        tcp_header->th_urp = 0;
        tcp_header->th_sum = checksum(psuedo_header, tcp_header);
    } else {
        udp_header->uh_sport = htons(our_port);
        udp_header->uh_dport = htons(curr_port);
        udp_header->len = htons(8);
        udp_header->check = 0;
        udp_header->check = checksum(psuedo_header, udp_header);
    }
}


int initSocket(){
    //creeate IPV4 Raw socket, TCP protocol
    int s;
    struct timeval tv_out;

    if (isTCP){
        s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    } else{
        s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        ICMP_SOCK = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (ICMP_SOCK < 0){
            perror("socket");
            fprintf(stderr, "You need to be root to create raw sockets!\n");
            return -1;
        }
    }
    //if the socket was not created successfully, we print we need sudo
    if (s < 0) {
        perror("socket");
        fprintf(stderr, "You need to be root to create raw sockets!\n");
        return -1;
    }
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

    if (!isTCP){
        int success = setsockopt(ICMP_SOCK, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));
        if (success < 0) {
            perror("setsockopt SO_RCVTIMEO");
            close(s);
            return -1;
        }
    }
    //if ok we return the socket.
    return s;
}

LinkedList *add_port(LinkedList *ls, u_int16_t port){
    if (ls == NULL){
        ls = (LinkedList *)calloc(1, sizeof(LinkedList));
        ls->port = port;
        return ls;
    }

    LinkedList * curr = ls;
    while (curr->next != NULL)
    {
        curr = curr->next;
    }
    curr->next = (LinkedList *)calloc(1, sizeof(LinkedList));
    curr->next->port = port;

    return ls;
}

void print_scan_results(LinkedList * head) {
    LinkedList * current = head;
    int count = 0;
    printf("found the next open port:\n\n");
    printf("[");
    while (current != NULL) {
        count++;
        if(count % 5){
            printf("%d, ", current->port);
            current = current->next;
        }else{
            printf("%d\n", current->port);
            current = current->next;
        }
    }
    printf("]\n\n");
}

void cleanup(LinkedList *ls){
    LinkedList *next = NULL;
    LinkedList *curr = ls;
    while (curr != NULL)
    {
        next = curr->next;
        free(curr);
        curr = next;
    };
    free(dest);
    free(src);
    free(psuedo_header);
    free(tcp_header);
    free(udp_header);
}

void release_node(LinkedList *ls){
    if (ls != NULL)
    {
        release_node(ls->next);
    }
    free(ls);
}

uint32_t get_local_ip() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8"); // Doesn't need to be reachable
    serv.sin_port = htons(53);

    // This doesn't send a packet, it just maps the route
    if (connect(sock, (const struct sockaddr*)&serv, sizeof(serv)) < 0) {
        close(sock);
        return 0;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr*)&name, &namelen) < 0) {
        close(sock);
        return 0;
    }

    close(sock);
    return name.sin_addr.s_addr;
}