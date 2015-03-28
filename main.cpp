#include <iostream>
#include <string>
#include "util.h"
#include "client.h"

using namespace std;

int main (int argc, char *argv[]) {
	display_start_message();
	if ( argc == 2 ) {
		char *dev = argv[1];
		pcap_t *handle;
		char ebuf[500];
		handle = pcap_open_live(dev,500,1,1000,ebuf);
		if ( !handle ) {
			fatalerror(ebuf);
		}
		prompt("Enter which side of the program you want to run: (1) Server (2) Client");
		int query;
		cin >> query;
		if ( query == 1 ) {
			server(handle);
		} else if ( query == 2 ) {
			client(handle);
		} else {
			fatalerror("Un-recognized input. Expected either 1 or 2.");
		}
	} else {
		fatalerror("Usage:\n\t./wifi-math interface");
	}
	display_end_message();
	return 0;
}
