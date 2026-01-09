# pragma once

// --- Defines ---

#define MAX_PORTS 100000
#define TIMEOUT 1
#define START_RANGE 1
#define MAX_RANGE 8085
// 65535
// --- Structs ---

typedef struct psuedo_header{
    uint32_t src;
    uint32_t dest;
    uint8_t fixed;
    uint8_t protocol;
    uint16_t segment_length;

} Psuedo_Header;

typedef struct linked_list{
    uint16_t port;
    struct linked_list *next;
} LinkedList;

// --- Function declaration ---
int parseArguments(int argc, char *argv[]);
int init();
unsigned short int checksum(Psuedo_Header *ps, void* protocl_h);
unsigned int calculate_sum(void *data, unsigned int bytes);
void prepare_packet(uint8_t flag);
LinkedList *add_port(LinkedList *ls, uint16_t port);
void print_scan_results(LinkedList * head);
void cleanup(LinkedList *ls);
void release_node(LinkedList *ls);
uint32_t get_local_ip();