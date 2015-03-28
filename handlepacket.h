#ifndef _HANDLEPACKET_H_
#define _HANDLEPACKET_H_

#include <pcap.h>

void send_packet(pcap_t*, MathPacketHeader, u_int8_t, int);


#endif