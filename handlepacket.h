#ifndef _HANDLEPACKET_H_
#define _HANDLEPACKET_H_

#include <pcap.h>
#include "packetheader.h"

void send_packet_with_data(pcap_t*, MathPacketHeader, u_int8_t, int);
void send_ack_packet(pcap_t*, MathPacketHeader);
void get_ack_packet(pcap_t*,MathPacketHeader*);
void get_MathPacketHeader(pcap_t*,MathPacketHeader*);
void get_packetinfo (pcap_t*, pcap_pkthdr*, u_char , MathPacketHeader*, u_int8_t);
bool is_math_type_request(MathPacketHeader);
bool is_math_type_ack_request(MathPacketHeader);
bool is_math_type_send_answer(MathPacketHeader);
bool is_math_type_ack_answer(MathPacketHeader);
bool is_request_id_same(MathPacketHeader, u_int32_t);

#endif
