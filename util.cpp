#include "util.h"
#include <iostream>
#include <string>
#include <cstdlib>

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[1;31m"
#define KGRN  "\x1B[1;32m"
#define KYEL  "\x1B[1;33m"
#define KBLU  "\x1B[1;34m"
#define KMAG  "\x1B[1;35m"
#define KCYN  "\x1B[1;36m"
#define KWHT  "\x1B[1;37m"

bool checkinput ( string input ) {
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
	display_end_message():
	exit(-1);
}

void warning (std::string warn_message) {
	std::cout << KYEL << "! " << warn_message << KNRM << std::endl;
}

void ack_message (std::string ack) {
	std::cout << KGRN << "+ " << ack << KNRM << std::endl;
}

void display_message_related_to_packet (std::string message) {
	std::cout << KBLU << "> " << message << KNRM << std::endl;
}

void display_end_message () {
	std::cout << KCYN << "=======Copyright (c) 2015 Rakholiya Jenish=======" << KNRM << std::endl;
}
