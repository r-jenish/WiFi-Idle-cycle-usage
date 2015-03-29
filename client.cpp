#include <cstdlib>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <pcap.h>
#include "client.h"
#include "infixtopostfix.h"
#include "packetheader.h"
#include "util.h"
#include "handlepacket.h"

using namespace std;

#define max_number_of_operands 7007

namespace {
	u_int16_t number_of_operands;
	int32_t operands[max_number_of_operands];
	u_int8_t operators[max_number_of_operands-1];                                   // Defined by the MATH_OPERATOR_* constants
	u_int8_t number_of_operators_after_operand[max_number_of_operands];             // The positions of the operators is as required for Reverse Polish Notation.
	int32_t answer = 0;
	const u_int16_t end_packet_magic_number = 21845;                                // Must be set to 21845
	u_int32_t user_id_of_requester;
	u_int32_t user_id_of_sender;
	u_int32_t request_id;
};

void fill_array (string postfix) {
	u_int16_t operands_iterator = 0;
	u_int16_t operator_iterator = 0;
	u_int16_t nooao_iterator = 0;                                               //number_of_operators_after_operand_iterator
	string num;
	for ( int string_iterator = 0; string_iterator < postfix.length(); string_iterator++ ) {
		if ( postfix[string_iterator] == ' ' ) continue;
		if ( postfix[string_iterator] >= '0' && postfix[string_iterator] <= '9' ) {
			num = "";
			num += postfix[string_iterator];
			while ( postfix[string_iterator+1] != ' ' ) {
				string_iterator++;
				num += postfix[string_iterator];
			}
			operands[operands_iterator] = atoi(num.c_str());
			nooao_iterator = operands_iterator;
			number_of_operators_after_operand[nooao_iterator] = 0;
			operands_iterator++;
		}
		switch ( postfix[string_iterator] ) {
			case '+':
				operators[operator_iterator] = MATH_OPERATOR_PLUS;
				operator_iterator++;
				number_of_operators_after_operand[nooao_iterator]++;
				break;
			case '-':
				operators[operator_iterator] = MATH_OPERATOR_MINUS;
				operator_iterator++;
				number_of_operators_after_operand[nooao_iterator]++;
				break;
			case '*':
				operators[operator_iterator] = MATH_OPERATOR_MULTIPLY;
				operator_iterator++;
				number_of_operators_after_operand[nooao_iterator]++;
				break;
			case '/':
				operators[operator_iterator] = MATH_OPERATOR_DIVIDE;
				operator_iterator++;
				number_of_operators_after_operand[nooao_iterator]++;
				break;
			case '%':
				operators[operator_iterator] = MATH_OPERATOR_MODULO;
				operator_iterator++;
				number_of_operators_after_operand[nooao_iterator]++;
				break;
			case '&':
				operators[operator_iterator] = MATH_OPERATOR_BITWISE_AND;
				operator_iterator++;
				number_of_operators_after_operand[nooao_iterator]++;
				break;
			case '|':
				operators[operator_iterator] = MATH_OPERATOR_BITWISE_OR;
				operator_iterator++;
				number_of_operators_after_operand[nooao_iterator]++;
				break;
			case '^':
				operators[operator_iterator] = MATH_OPERATOR_BITWISE_XOR;
				operator_iterator++;
				number_of_operators_after_operand[nooao_iterator]++;
				break;
		}
	}
	number_of_operands = operands_iterator;
}

namespace {
	void send_packet ( pcap_t *handle, MathPacketHeader header ) {
		u_int8_t buffer[900];
		if ( header.type_of_packet == MATH_TYPE_REQUEST ) {
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
		} else if ( header.type_of_packet == MATH_TYPE_ACK_ANSWER ) {
			send_ack_packet(handle,header);
		}
	}

	bool get_ack (pcap_t *handle, MathPacketHeader *header) {
		MathPacketHeader temphead;
		if ( get_ack_packet(handle,&temphead) && 
			 is_request_id_same(temphead,request_id) && 
			 temphead.type_of_packet == MATH_TYPE_ACK_REQUEST ) {
			user_id_of_sender = temphead.user_id_of_sender;
			return true;
		}
		return false;
	}

	bool get_ans_packet (pcap_t *handle, MathPacketHeader header) {
		MathPacketHeader temphead;
		u_int8_t buffer[1000];
		int32_t ans;
		if ( get_packet(handle,&temphead,buffer) && 
			 is_request_id_same(temphead,request_id) && 
			 temphead.type_of_packet == MATH_TYPE_SEND_ANSWER ) {
			memcpy(&ans,buffer+6*number_of_operands-1,4);
			answer = ans;
			return true;
		}
		return false;
	}
};

void client (pcap_t *handle) {
	string infix;
	string postfix;
	prompt("Enter the expression in infix notation: ");
	cin >> infix;
	if ( !checkinput(infix) ) {
		fatalerror("Incorrect input format");
	}
	postfix = infix_to_postfix(infix);
	fill_array(postfix);
	user_id_of_requester = get_user_id_of_requester();
	user_id_of_sender = 0;
	request_id = generate_request_id();
	MathPacketHeader header;
	header.magic_number = 9770010;
	header.user_id_of_requester = user_id_of_requester;
	header.user_id_of_sender = user_id_of_sender;
	header.request_id = request_id;
	header.number_of_operands = number_of_operands;
	//send request
	display_message_related_to_packet("Sending request to a server.");
	header.type_of_packet = MATH_TYPE_REQUEST;
	send_packet(handle,header);
	int c = 0;
	while ( !get_ack(handle,&header) ) {
		header.type_of_packet = MATH_TYPE_REQUEST;
		c = (c+1)%100;
		if ( c == 0 )
			send_packet(handle,header);
	}
	ack_message("Request acknowledged by the server.");
	header.user_id_of_sender = user_id_of_sender;
	display_message_related_to_packet("Waiting for answer from the server.");
	while ( !get_ans_packet(handle,header) );
	ack_message("Answer received from the server.");
	display_message_related_to_packet("Sending answer received acknowledgement.");
	header.type_of_packet = MATH_TYPE_ACK_ANSWER;
	for ( int i = 0; i < 1000; i++ ) {
			send_packet(handle,header);
	}
	display_answer(answer);
}
