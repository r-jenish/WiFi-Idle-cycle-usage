#include <iostream>
#include <pcap.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <stack>
#include "util.h"
#include "packetheader.h"
#include "handlepacket.h"

using namespace std;

#define max_number_of_operands 7007

namespace {
	u_int16_t number_of_operands;
	int32_t operands[max_number_of_operands];
	u_int8_t operators[max_number_of_operands-1];                                   // Defined by the MATH_OPERATOR_* constants
	u_int8_t number_of_operators_after_operand[max_number_of_operands];             // The positions of the operators is as required for Reverse Polish Notation.
	int32_t answer = 0;
	const u_int16_t end_packet_magic_number = 21845;
	u_int32_t user_id_of_requester;
	u_int32_t user_id_of_sender;
	u_int32_t request_id;
};

int calcans () {
	stack<int> S;
	int operators_iterator = 0;
	int nooao = 0;
	for ( int i = 0; i < number_of_operands; i++ ) {
		S.push(operands[i]);
		nooao = number_of_operators_after_operand[i];
		while ( nooao > 0 ) {
			int b = S.top();
			S.pop();
			int a = S.top();
			S.pop();
			switch ( operators[operators_iterator] ) {
				case MATH_OPERATOR_PLUS:
					S.push(a+b);
					break;
				case MATH_OPERATOR_MINUS:
					S.push(a-b);
					break;
				case MATH_OPERATOR_MULTIPLY:
					S.push(a*b);
					break;
				case MATH_OPERATOR_DIVIDE:
					S.push(a/b);
					break;
				case MATH_OPERATOR_MODULO:
					S.push(a%b);
					break;
				case MATH_OPERATOR_BITWISE_AND:
					S.push(a&b);
					break;
				case MATH_OPERATOR_BITWISE_OR:
					S.push(a|b);
					break;
				case MATH_OPERATOR_BITWISE_XOR:
					S.push(a^b);
					break;
			}
			operators_iterator++;
			nooao--;
		}
	}
	return S.top();
}

void fill_array_from_packet( u_int8_t buffer[] ) {
	int lengthread = 0;
	memcpy(operands,buffer,number_of_operands*4);
	lengthread += number_of_operands*4;
	memcpy(operators,buffer+lengthread,number_of_operands-1);
	lengthread += (number_of_operands-1);
	memcpy(number_of_operators_after_operand,buffer+lengthread,number_of_operands);
	lengthread += number_of_operands;
	memcpy(&answer,buffer+lengthread,4);
}

namespace {
	void send_packet ( pcap_t *handle, MathPacketHeader header ) {
		u_int8_t buffer[900];
		if ( header.type_of_packet == MATH_TYPE_SEND_ANSWER ) {
			int packet_size = 0;
			memcpy(buffer,operands,number_of_operands*4);
			packet_size += number_of_operands*4;
			memcpy(buffer+packet_size,operators,number_of_operands-1);
			packet_size += (number_of_operands-1);
			memcpy(buffer+packet_size,number_of_operators_after_operand,number_of_operands);
			packet_size += number_of_operands;
			memcpy(buffer+packet_size,&answer,4);
			packet_size += 4;
			memcpy(buffer+packet_size,&end_packet_magic_number,2);
			packet_size += 2;
			send_packet_with_data(handle,header,buffer,packet_size);
		} else if ( header.type_of_packet == MATH_TYPE_ACK_REQUEST ) {
			send_ack_packet(handle,header);
		}
	}

	bool get_ack (pcap_t *handle) {
		MathPacketHeader temphead;
		return ( get_ack_packet(handle,&temphead) && 
				 temphead.type_of_packet == MATH_TYPE_ACK_ANSWER && 
				 is_request_id_same(temphead,request_id) );
	}

	bool get_req_packet (pcap_t *handle, MathPacketHeader *header, u_int8_t pktbuf[]) {
		return ( get_packet(handle,header,pktbuf) && 
				 header->type_of_packet == MATH_TYPE_REQUEST);
	}
};

void server (pcap_t *handle) {	
	MathPacketHeader header;
	u_int8_t buffer[1000];
	user_id_of_sender = get_user_id_of_sender();
	user_id_of_requester = 0;
	request_id = 0;
	//get packet
	while ( !get_req_packet(handle,&header,buffer) );
	display_message_related_to_packet("Answer requested by a client.");
	header.user_id_of_sender = user_id_of_sender;
	user_id_of_requester = header.user_id_of_requester;
	request_id = header.request_id;
	number_of_operands = header.number_of_operands;
	fill_array_from_packet(buffer);
	display_message_related_to_packet("Sending request arrived acknowledgement.");
	for ( int i = 0; i < 1000; i++ ) {
		header.type_of_packet = MATH_TYPE_ACK_REQUEST;
		send_packet(handle,header);
	}
	display_message_related_to_packet("Calulating answer.");
	answer = calcans();
	display_message_related_to_packet("Sending answer to the client.");
	header.type_of_packet = MATH_TYPE_SEND_ANSWER;
	send_packet(handle,header);
	int c = 0;
	while ( !get_ack(handle) ) {
		header.type_of_packet = MATH_TYPE_SEND_ANSWER;
		c = (c+1)%100;
		if ( c == 0 )
			send_packet(handle,header);
	}
	ack_message("Answer received by client.");
}
