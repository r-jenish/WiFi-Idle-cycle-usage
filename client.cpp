#include <cstdlib>
#include <iostream>
#include <string>
#include <pcap.h>
#include "client.h"
#include "infixtopostfix.h"
#include "packetheader.h"
#include "util.h"
#include "handlepacket.h"

using namespace std;

#define max_number_of_operands 7007

u_int16_t number_of_operands;
int32_t operands[max_number_of_operands];
u_int8_t operators[max_number_of_operands-1];                                   // Defined by the MATH_OPERATOR_* constants
u_int8_t number_of_operators_after_operand[max_number_of_operands];             // The positions of the operators is as required for Reverse Polish Notation.
int32_t answer = 0;
const u_int16_t end_packet_magic_number = 21845;                                // Must be set to 21845

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

void send_packet ( pcap *handle, MathPacketHeader header, u_int8_t type ) {
	if ( type == MATH_TYPE_REQUEST ) {
		//SEND REQUEST TYPE PACKET
		header.type_of_packet = MATH_TYPE_REQUEST;

	} else if ( type == MATH_TYPE_ACK_ANSWER ) {
		//SEND ACK ANSWER
		header.type_of_packet = MATH_TYPE_ACK_ANSWER;
		send_ack_packet(handle,header);
	}
}

void client ( pcap_t *handle ) {
	string infix;
	string postfix;
	prompt("Enter the expression in infix notation: ");
	cin >> infix;
	if ( !checkinput(infix) ) {
		fatalerror("Incorrect input format");
	}
	postfix = infix_to_postfix(infix);
	fill_array(postfix);
	
	MathPacketHeader header;
	header.magic_number = 9770010;
	header.user_id_of_requester = get_user_id_of_requester();
	header.user_id_of_sender = 0;
	header.request_id = generate_request_id();
	header.number_of_operands = number_of_operands;
	//send packet until ack or ans is received
	//display answer
	//send ans ack
	/*
	send_packet(handle,header,MATH_TYPE_REQUEST);
	MathPacketHeader temp;
	while (ture) {
		get_ack_packet(handle,&temp);
		if ( is_type_ack_request(temp) && is_request_id_same(header,temp) ) {
			header.user_id_of_sender = temp.user_id_of_sender;
			return true;
		} else {
			return false;
		}
	}
	header.user_id_of_sender = tempid;
	while ( !get_answer(handle, header) );
	send_packet(handle,header,MATH_TYPE_ACK_ANSWER);
	*/
}
