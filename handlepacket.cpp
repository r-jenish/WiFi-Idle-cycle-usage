#include <iostream>

#include <pcap.h>
#include <string>
#include <cstdlib>
#include <cstring>
#include "packetheader.h"
#include "handlepacket.h"

using namespace std;

void send_packet_with_data (pcap_t *handle, MathPacketHeader header ,u_int8_t buffer[], int length) {
	u_int8_t sendbuffer[1000];
	int packetsize = 0;
	wrap_datalink(pcap_datalink(handle),sendbuffer,&packetsize);
	memcpy(sendbuffer+packetsize,&header,19);
	packetsize += 19;
	memcpy(sendbuffer+packetsize,buffer,length);
	packetsize += length;
	pcap_inject(handle,sendbuffer,packetsize);
}

void send_ack_packet (pcap_t *handle, MathPacketHeader header) {
	u_int8_t sendbuffer[50];
	int packetsize = 0;
	wrap_datalink(pcap_datalink(handle),sendbuffer,&packetsize);
	memcpy(sendbuffer+packetsize,&header,19);
	packetsize += 19;
	pcap_inject(handle,sendbuffer,packetsize);
}

bool get_packet (pcap_t *handle, MathPacketHeader *header, u_int8_t pktbuffer[] ) {
	u_int8_t buffer[1000];
	pcap_pkthdr hdr;
	MathPacketHeader temphead;
	const u_char* temp = pcap_next(handle,&hdr);
	if ( hdr.len >= 27 && hdr.len <= 1000 ) {
		memcpy(buffer,temp,hdr.len);
		get_MathPacketHeader(handle,buffer,&temphead);
		if (temphead.number_of_operands <= 165) {
			get_packetinfo(handle,&hdr,buffer,header,pktbuffer);
			return ( header->magic_number == 9770010 && 
				     (is_math_type_request(*header) || is_math_type_send_answer(*header)) );
		}
	}
	return false;
}

bool get_ack_packet (pcap_t *handle, MathPacketHeader *header) {
	u_int8_t buffer[1000];
	pcap_pkthdr hdr;
	const u_char* temp = pcap_next(handle,&hdr);
	if ( hdr.len >= 27 && hdr.len <= 1000 ) {
		memcpy(buffer,temp,hdr.len);
		get_MathPacketHeader(handle,buffer,header);
		return ( header->magic_number == 9770010 && 
			(is_math_type_ack_request(*header) || is_math_type_ack_answer(*header)) );
	} else {
		return false;
	}
}

void get_MathPacketHeader (pcap_t *handle, u_int8_t packet[], MathPacketHeader *header) { // help with pointer
	int length = 0;
	length = datalink_length(pcap_datalink(handle),packet);
	memcpy(header,packet+length,19);
}

void get_packetinfo (pcap_t *handle, pcap_pkthdr *hdr, u_char packet[], MathPacketHeader *header, u_int8_t buffer[]) {
	int length = 0;
	length = datalink_length(pcap_datalink(handle),packet);
	memcpy(header,packet+length,19);
	length+=19;
	memcpy(buffer,packet+length,6*header->number_of_operands+5);
}

void wrap_datalink ( int datalink, u_int8_t buffer[], int *length) {
	if ( datalink == DLT_PRISM_HEADER ) {
		const u_int8_t prismHeader[] = {
			0x00, 0x00, 0x00, 0x41,
			0x08, 0x00, 0x00, 0x00
		};
		memcpy(buffer,prismHeader,sizeof(prismHeader));
		*length += sizeof(prismHeader);
	} else if ( datalink == DLT_IEEE802_11_RADIO ) {
		const u_int8_t radiotapHeader[] = { 
			0x00, 0x00,
			0x08, 0x00,
			0x04, 0x0c, 0x00, 0x00,
		};
		memcpy(buffer,radiotapHeader,sizeof(radiotapHeader));
		*length += sizeof(radiotapHeader);
	}
}

int datalink_length ( int datalink, u_int8_t packet[] ) {
	int length = 0;
	if ( datalink == DLT_PRISM_HEADER ) {
		prism_header* hdr = (prism_header*)(packet);
		length = hdr->msglen;
	} else if ( datalink == DLT_IEEE802_11_RADIO ) {
		ieee80211_radiotap_header* hdr = (ieee80211_radiotap_header*)(packet);
		length = hdr->it_len;
	}
	return length;
}

inline bool is_math_type_request ( MathPacketHeader header ) {
	return header.type_of_packet == MATH_TYPE_REQUEST;
}

inline bool is_math_type_ack_request ( MathPacketHeader header ) {
	return header.type_of_packet == MATH_TYPE_ACK_REQUEST;
}

inline bool is_math_type_send_answer ( MathPacketHeader header ) {
	return header.type_of_packet == MATH_TYPE_SEND_ANSWER;
}

inline bool is_math_type_ack_answer ( MathPacketHeader header ) {
	return header.type_of_packet == MATH_TYPE_ACK_ANSWER;
}

bool is_request_id_same ( MathPacketHeader header, u_int32_t request_id ) {
	return header.request_id == request_id;
}
