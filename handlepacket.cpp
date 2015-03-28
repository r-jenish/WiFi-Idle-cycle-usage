#include <pcap.h>
#include <string>
#include <cstdlib>
#include "packetheader.h"

void send_packet (pcap_t *handle, MathPacketHeader header ,u_int8_t buffer[], int length) {
	u_int8_t sendbuffer[length+50];
	int packetsize = 0;
	if ( pcap_datalink(handle) == DLT_PRISM_HEADER ) {
		//add prism header to the starting of the packet and update packetsize
	} else if ( pcap_datalink(handle) == DLT_IEEE802_11_RADIO ) {
		//add radiotap header to the starting of the packet and update packetsize
	}
	memcpy(sendbuffer+packetsize,&header,19);
	packetsize += 19;
	memcpy(sendbuffer+packetsize,buffer,length);
	packetsize += length;
	pcap_inject(handle,sendbuffer,packetsize);
}

void get_MathPacketHeader () {

}