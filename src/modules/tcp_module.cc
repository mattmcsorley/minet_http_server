// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process



#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"

using namespace std;

struct TCPState {
    // need to write this
    std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()" ; 
	return os;
    }
};


int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;
    
    ConnectionList<TCPState> clist;

    MinetInit(MINET_TCP_MODULE);

    mux = MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
    
    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

    if ( (mux == MINET_NOHANDLE) && (MinetIsModuleInConfig(MINET_IP_MUX)) ) {
		MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));
		return -1;
    }

    if ( (sock == MINET_NOHANDLE) && (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {
		MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));
		return -1;
    }
    
    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));

    MinetEvent event;
    double timeout = 1;

    while (MinetGetNextEvent(event, timeout) == 0) {

	if ((event.eventtype == MinetEvent::Dataflow) && 
	    (event.direction == MinetEvent::IN)) {
	
	    if (event.handle == mux) {
		// ip packet has arrived!
	    	printf("MUXXXXX \n");
	    	Packet p;
	    	unsigned char header_len;
	    	unsigned short total_len;
	    	unsigned char flags;
	    	unsigned int ack_num;
	    	unsigned int seq_num;
	    	bool checksumok;
	    	TCPHeader tcph;
	    	IPHeader iph;

	    	MinetReceive(mux,p);
	    	//Esimate heaader length
	    	header_len = TCPHeader::EstimateTCPHeaderLength(p);
	    	//Extract header with header_length size
	    	p.ExtractHeaderFromPayload<TCPHeader>(header_len);
	    
	    	
	    	//Put tcp header into tcph
	    	tcph = p.FindHeader(Headers::TCPHeader);
	    	//Calulate checksum
	    	checksumok=tcph.IsCorrectChecksum(p);
	    	
	    	//put IP header into iph
	    	iph=p.FindHeader(Headers::IPHeader);
	    	
	    	Connection c;
	    	//set connection variables
	    	iph.GetDestIP(c.src);
	    	iph.GetSourceIP(c.dest);
	    	iph.GetProtocol(c.protocol);
	    	tcph.GetDestPort(c.srcport);
	    	tcph.GetSourcePort(c.destport);
	    	//get tcp vars from tcp header
	    	tcph.GetFlags(flags);
	    	tcph.GetAckNum(ack_num);
	    	tcph.GetSeqNum(seq_num);


	    	ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
	    	

	    	if(cs != clist.end()) {
	    		if(cs.GetState() == LISTEN)
	    		{
	    			printf("LISTEN");

	    		}
	    		else if((*cs).state.GetState() == CLOSED){
	    			printf("CLOSED");

	    		}
	    		
	    		
	    		Buffer &data = p.GetPayload().ExtractFront(len);
	    		SockRequestResponse write(WRITE, 
	    				(*cs).connection,
	    				data,
	    				len,
	    				EOK);
	    		if(!checksumok) {
	    			MinetSendToMonitor(MinetMonitoringEvent("forwarding packet to sock even though checksum failed"));
	    		}
	    	} else {
	    		MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
	    		IPAddress source;
	    		iph.GetSourceIP(source);
	    		ICMPPacket error(source, DESTINATION_UNREACHABLE,PORT_UNREACHABLE,p);
	    		MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to host"));
	    		MinetSend(mux,error);
	    	}
	    }

	    if (event.handle == sock) {
		// socket request or response has arrived
	    	
	    }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    // timeout ! probably need to resend some packets
	}

    }

    MinetDeinit();

    return 0;
}
