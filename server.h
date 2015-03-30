#ifndef _SERVER_H_
#define _SERVER_H_ value

#include <pcap.h>

int calcans();
void fill_array_from_packet(u_int8_t[]);
void server(pcap_t*);

#endif