#ifndef _UTIL_H_
#define _UTIL_H_
#include <pcap.h>
#include <string>

bool checkinput(std::string);
void fatalerror(std::string);
void warning(std::string);
void prompt(std::string);
void ack_message(std::string);
void display_message_related_to_packet(std::string);
void display_answer(int32_t);
void display_start_message();
void display_end_message();
u_int32_t get_user_id_of_requester();
u_int32_t get_user_id_of_sender();
u_int32_t generate_request_id();

#endif
