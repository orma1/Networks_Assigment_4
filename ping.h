#pragma once
void cleanup();
int parseArguments(int argc, char *argv[], struct in_addr *ip, int* aFlagExists, int* count, int* flood);
int initSocket();
void * initDestStruct(struct in_addr * dest_addr);
void start_ping_message(struct in_addr * dest_addr);
void prep_packet(char * sendBuffer, int seqNum);