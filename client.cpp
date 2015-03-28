#include <cstdlib>
#include <iostream>
#include <string>
#include <pcap.h>

#include "client.h"
#include "util.h"

using namespace std;

void client () {
	string infix;
	prompt("Enter the expression in infix notation: ");
	cin >> infix;
	if ( !checkinput(infix) ) {
		fatalerror("Incorrect input format");
	}
	convert_to_postfix(infix);						//Convert infix to postfix
	
}
