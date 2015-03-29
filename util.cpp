#include "util.h"
#include <iostream>
#include <string>
#include <cstdlib>
#include <pcap.h>

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[1;31m"		//error
#define KGRN  "\x1B[1;32m"		//ack or any other stuff that got completed successfully
#define KYEL  "\x1B[1;33m"		//warn
#define KBLU  "\x1B[1;34m"		//ongoing process
#define KMAG  "\x1B[1;35m"		//prompt
#define KCYN  "\x1B[1;36m"		//end
#define KWHT  "\x1B[1;37m"

bool checkinput ( std::string input ) {
	for ( int i = 0; i < input.length(); i++ ) {
		if ( (input[i] >= '0' && input[i] <= '9') ||
			  input[i] == '+'                     ||
			  input[i] == '-'                     ||
			  input[i] == '*'                     ||
			  input[i] == '/'                     ||
			  input[i] == '%'                     ||
			  input[i] == '^'                     ||
			  input[i] == '|'                     ||
			  input[i] == '&'                       ) continue;
		else return false;
	}
	return true;
}

void fatalerror (std::string err_message) {
	std::cout << KRED << "- " << err_message << KNRM << std::endl;
	display_end_message();
	exit(-1);
}

void warning (std::string warn_message) {
	std::cout << KYEL << "! " << warn_message << KNRM << std::endl;
}

void prompt (std::string message) {
	std::cout << KMAG << "? " << message << KNRM << std::endl;
}

void ack_message (std::string ack) {
	std::cout << KGRN << "+ " << ack << KNRM << std::endl;
}

void display_message_related_to_packet (std::string message) {
	std::cout << KBLU << "> " << message << KNRM << std::endl;
}

void display_answer ( int32_t answer ) {
	std::cout << KWHT << "++> Answer for the given expression is: " << answer << KNRM << std::endl;
}

void display_start_message () {
	std::cout << KCYN << "=======DISTRIBUTED NETWORK MATH CALCULATOR=======" << KNRM << std::endl;
}

void display_end_message () {
	std::cout << KCYN << "=======Copyright (c) 2015 Rakholiya Jenish=======" << KNRM << std::endl;
}

u_int32_t get_user_id_of_requester () {
	return rand()%42949672;
}

u_int32_t get_user_id_of_sender () {
	return rand()%42949672;
}

u_int32_t generate_request_id () {
	return rand()%42949672;
}
