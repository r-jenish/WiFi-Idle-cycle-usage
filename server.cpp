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

void server (pcap_t *handle) {	
	MathPacketHeader header;
	//get packet
	//send ack
	answer = calcans();
	//send ans
	//wait for ack
}