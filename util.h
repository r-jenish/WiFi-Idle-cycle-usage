#ifndef _UTIL_H_
#define _UTIL_H_
#include <string>

bool checkintput (std::string);
void fatalerror(std::string);
void warning(std::string);
void prompt(std::string);
void ack_message(std::string);
void display_message_related_to_packet(std::string);
void display_end_message();

#endif
