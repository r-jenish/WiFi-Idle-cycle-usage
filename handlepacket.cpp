#include <pcap.h>
#include <string>
#include <cstdlib>
#include <cstring>
#include "packetheader.h"
#include "handlepacket.h"

void send_packet_with_data (pcap_t *handle, MathPacketHeader header ,u_int8_t buffer[], int length) {
	u_int8_t sendbuffer[length+50];
	int packetsize = 0;
	if ( pcap_datalink(handle) == DLT_PRISM_HEADER ) {
		//add prism header to the starting of the packet and update packetsize
	} else if ( pcap_datalink(handle) == DLT_IEEE802_11_RADIO ) {
		//add radiotap header to the starting of the packet and update packetsize
	}
	memcpy(sendbuffer+packetsize,&header,19);
	packetsize += 19;
	memcpy(sendbuffer+packetsize,buffer,length);
	packetsize += length;
	pcap_inject(handle,sendbuffer,packetsize);
}

void send_ack_packet (pcap_t *handle, MathPacketHeader header ) {
	u_int8_t sendbuffer[50];
	int packetsize = 0;
	if ( pcap_datalink(handle) == DLT_PRISM_HEADER ) {
		//add prism header to the starting of the packet and update packetsize
	} else if ( pcap_datalink(handle) == DLT_IEEE802_11_RADIO ) {
		//add radiotap header to the starting of the packet and update packetsize
	}
	memcpy(sendbuffer+packetsize,&header,19);
	packetsize += 19;
	pcap_inject(handle,sendbuffer,packetsize);
}

void get_ack_packet (pcap_t *handle, MathPacketHeader *header) {
	u_int8_t buffer[100];
	pcap_pkthdr *hdr;
	//buffer = pcap_next(handle,hdr);
	get_MathPacketHeader(handle,header);
}

void get_MathPacketHeader (pcap_t *handle, MathPacketHeader *header) { // help with pointer
	int length = 0;
	if ( pcap_datalink(handle) == DLT_PRISM_HEADER ) {
		//length += something 
	} else if ( pcap_datalink(handle) == DLT_IEEE802_11_RADIO ) {
		//length += something
	}
	memcpy(header,packet+length,19);
	length+=19;
}

void get_packetinfo (pcap_t *handle, pcap_pkthdr *hdr, u_char packet[], MathPacketHeader *header, u_int8_t buffer[]) {
	int length = 0;
	if ( pcap_datalink(handle) == DLT_PRISM_HEADER ) {
		//length += something 
	} else if ( pcap_datalink(handle) == DLT_IEEE802_11_RADIO ) {
		//length += something
	}
	memcpy(header,packet+length,19);
	length+=19;
	memcpy(buffer,packet+length,11/*check it*/);
}

bool is_math_type_request ( MathPacketHeader header ) {
	if ( header.type_of_packet == MATH_TYPE_REQUEST ) {
		return true;
	}
	return false;
}

bool is_math_type_ack_request ( MathPacketHeader header ) {
	if ( header.type_of_packet == MATH_TYPE_ACK_REQUEST ) {
		return true;
	}
	return false;
}

bool is_math_type_send_answer ( MathPacketHeader header ) {
	if ( header.type_of_packet == MATH_TYPE_SEND_ANSWER ) {
		return true;
	}
	return false;
}

bool is_math_type_ack_answer ( MathPacketHeader header ) {
	if ( header.type_of_packet == MATH_TYPE_ACK_ANSWER ) {
		return true;
	}
	return false;
}

bool is_request_id_same ( MathPacketHeader header, u_int32_t request_id ) {
	if ( header.request_id == request_id ) {
		return true;
	}
	return false;
}
