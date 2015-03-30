#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <string>
#include <pcap.h>
#include "packetheader.h"

void fill_array(std::string);
void send_packet(pcap_t*, MathPacketHeader);
void client(pcap_t*);

#endif
