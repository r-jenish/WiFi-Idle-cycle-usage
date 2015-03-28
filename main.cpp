#include <iostream>
#include <string>
#include "util.h"

using namespace std;

int main () {
	display_start_message();
	prompt("Enter which side of the program you want to run: (1) Server (2) Client");
	string query;
	cin >> query;
	if ( query == '1' ) {
		server();
	} else if ( query == '2' ) {
		client();
	} else {
		fatalerror("Un-recognized input. Accepted either 1 or 2.");
	}
	display_end_message();
	return 0;
}
