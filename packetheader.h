#ifndef _PACKET_HEADER_H_
#define _PACKET_HEADER_H_

#include <pcap.h>

const u_int8_t MATH_TYPE_REQUEST     = 1; // Request for an expression to be solved
const u_int8_t MATH_TYPE_ACK_REQUEST = 2; // Acknowledge request and start solving
const u_int8_t MATH_TYPE_SEND_ANSWER = 4; // Send answer
const u_int8_t MATH_TYPE_ACK_ANSWER  = 8; // Acknowledge received answer

struct MathPacketHeader {
    u_int32_t magic_number; // Must be set to 9770010
    u_int8_t type_of_packet; // MATH_TYPE_*
    u_int32_t user_id_of_requester; // Single unique integer, upto 4294967295
    u_int32_t user_id_of_sender; // Single unique integer, upto 4294967295
    u_int32_t request_id; // Single unique integer, upto 4294967295
    u_int16_t number_of_operands;
} __attribute__((__packed__));

const u_int8_t MATH_OPERATOR_PLUS        = 1;
const u_int8_t MATH_OPERATOR_MINUS       = 2;
const u_int8_t MATH_OPERATOR_MULTIPLY    = 3;
const u_int8_t MATH_OPERATOR_DIVIDE      = 4;
const u_int8_t MATH_OPERATOR_MODULO      = 5;
const u_int8_t MATH_OPERATOR_BITWISE_AND = 6;
const u_int8_t MATH_OPERATOR_BITWISE_OR  = 7;
const u_int8_t MATH_OPERATOR_BITWISE_XOR = 8;

struct ieee80211_radiotap_header {
	u_int8_t it_version;     /* set to 0 */
	u_int8_t it_pad;
	u_int16_t it_len;         /* entire length */
	u_int32_t it_present;     /* fields present */
} __attribute__((__packed__));

struct prism_header {
	u_int32_t msgcode;
	u_int32_t msglen;
} __attribute__((__packed__));

#endif
