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

struct TCPState;
struct TCP;
struct TCPStateListen;


struct TCP
{
	
	TCPState *state;
	unsigned int seq_num;
	unsigned int ack_num;
	unsigned char flags;
	unsigned short sourcePort;
	unsigned short destPort;
	unsigned short winSize;
	unsigned char ipHeaderLen;
	unsigned char protocol;
	IPAddress sourceIP;
	IPAddress destIP;
	unsigned short ipLen;


	TCP();
	
	Packet* receive(Packet p);
	
};

struct TCPState 
{
    // need to write this
	TCP * outer;
	TCPState(TCP * out);

    virtual void send(){}
    virtual Packet* receive();

    std::ostream & Print(std::ostream &os) const 
    { 
		os << "TCPState()"; 
		return os;
    }
};


struct TCPStateListen : TCPState
{
	TCPStateListen(TCP * out);
	Packet* receive();	
};

/*
struct TCPStateEstablished : TCPState
{
	void receive(TCPHeader tcph, IPHeader iph)
	{
		// Do setup of packets to send

		// Sent to minet.

		//Change state.

		//outer.state = new TCPStateEstablished(outer);	

	}
};
*/
struct TCPStateSynRecv : TCPState
{
	TCPStateSynRecv(TCP * out);
	Packet* receive();
};
/*
struct TCPStateSynSent : TCPState
{
	void receive(TCPHeader tcph, IPHeader iph)
	{
		// Do setup of packets to send

		// Sent to minet.

		// Change state.

		//outer.state = new TCPStateEstablished(outer);	

	}
};
*/
Packet* TCP::receive(Packet p){
	printf("TCP receive\n");
	IPHeader iph;
	TCPHeader tcph;

	tcph = p.FindHeader(Headers::TCPHeader);
	tcph.GetSeqNum(seq_num);
	tcph.GetAckNum(ack_num);
	tcph.GetFlags(flags);
	cout << tcph << endl;
	tcph.GetSourcePort(this->sourcePort);
	tcph.GetDestPort(this->destPort);
	cout << "dest port: " << destPort << ", " << sourcePort << endl;
	tcph.GetWinSize(winSize);

	//cout << tcph << endl;
	iph=p.FindHeader(Headers::IPHeader);
	iph.GetSourceIP(sourceIP);
	iph.GetDestIP(destIP);
	iph.GetTotalLength(ipLen);
	iph.GetProtocol(protocol);
	iph.GetHeaderLength(ipHeaderLen);

	return state->receive();
}

Packet* TCPState::receive(){
	return new Packet();
}

TCP::TCP()
{
		ack_num = 300;
		state = new TCPStateListen(this);
		printf("TCP constructor\n");
}

TCPState::TCPState(TCP * out)
{
		outer = out;
		printf("TCPState Constructor\n");
}

TCPStateListen::TCPStateListen(TCP *out) : TCPState(out) {}
TCPStateSynRecv::TCPStateSynRecv(TCP *out) : TCPState(out) {}

Packet* TCPStateSynRecv::receive()
{
	return new Packet();
}
Packet* TCPStateListen::receive()
{
	printf("TCPStateListen received\n");
	printf("source test : %d\n", (*outer).sourcePort);
	printf("dest test : %d\n", (*outer).destPort);
	Packet *ret_val = NULL;

	if(IS_SYN(outer->flags))
	{
		cout << "IS_SYN" << endl;
		Packet outgoing_packet;
		IPHeader iph;
		TCPHeader tcph;

		iph.SetProtocol(outer->protocol);
		iph.SetSourceIP(outer->sourceIP);
		iph.SetDestIP(outer->destIP);
		iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
		outgoing_packet.PushFrontHeader(iph);

		tcph.SetSourcePort(outer->sourcePort,outgoing_packet);
        tcph.SetDestPort(outer->destPort,outgoing_packet);
        tcph.SetFlags(outer->flags,outgoing_packet);  
        tcph.SetSeqNum(outer->ack_num,outgoing_packet);   
        tcph.SetAckNum(outer->seq_num + 1,outgoing_packet);    
        tcph.SetWinSize(outer->winSize,outgoing_packet);
        tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH,outgoing_packet);
        outgoing_packet.PushBackHeader(tcph);		


		outer->state = new TCPStateSynRecv(outer);
		ret_val = &outgoing_packet;
	}

	cout << "Returning outgoing packet" << endl;
	return ret_val;
}

int main(int argc, char * argv[]) 
{
    MinetHandle mux;
    MinetHandle sock;
   
    ConnectionList<TCP *> clist;

    MinetInit(MINET_TCP_MODULE);

    mux = MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
    
    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

    if ((mux == MINET_NOHANDLE) && (MinetIsModuleInConfig(MINET_IP_MUX))) 
    {
		MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));
		return -1;
    }

    if ((sock == MINET_NOHANDLE) && (MinetIsModuleInConfig(MINET_SOCK_MODULE))) 
    {
		MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));
		return -1;
    }
    
    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));

    MinetEvent event;
    double timeout = 1;

    // Server initial state
    printf("Initializing");
	TCP initState;
	TCPStateListen listenState(&initState);
	initState.state = &listenState;


    // Client initial state
    /*
    */

    while (MinetGetNextEvent(event, timeout) == 0) 
    {

		if ((event.eventtype == MinetEvent::Dataflow) && (event.direction == MinetEvent::IN)) 
		{
		
		    if (event.handle == mux) 
		    {
				// ip packet has arrived!
		    	printf("MUXXXXX \n");
		    	Packet p;
		    	unsigned char header_len;
		    	bool checksumok;
		    	TCPHeader tcph;
		    	IPHeader iph;

		    	MinetReceive(mux,p);
		    	//Esimate header length
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
		    	// set connection variables
		    	iph.GetDestIP(c.src);
		    	iph.GetSourceIP(c.dest);
		    	iph.GetProtocol(c.protocol);
		    	tcph.GetDestPort(c.srcport);
		    	tcph.GetSourcePort(c.destport);
		    	//printf("test1\n");

				ConnectionToStateMapping<TCP *> * a = new ConnectionToStateMapping<TCP *>();
				printf("test1\n");
				printf("test2\n");
				printf("test3\n");
				printf("test4\n");
				printf("test5\n");
				printf("test6\n");
				Connection *conn = new Connection();
				conn->src = c.src;
				conn->dest = c.dest;
				conn->protocol = c.protocol;
				conn->srcport = c.srcport;
				conn->destport = c.destport;
				a->connection = *conn;
				a->state = &initState; 
		    	clist.push_back(*a);

		    	ConnectionList<TCP *>::iterator cs = clist.FindMatching(c);
		    	

		    	if(cs != clist.end()) 
		    	{
		    		Packet *receive_packet;
		    		printf("cs\n");
		    		receive_packet = (*cs).state->receive(p);

		    		if (receive_packet != NULL)
		    		{
		    			cout << "Sending in mux" << endl;
		    			MinetSend(mux,*receive_packet);
		    			cout << "Sent" << endl;
		    		}
		    	}
		    	else
		    	{
		    		printf("cs ELSE\n");
		    		MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
		    		IPAddress source;
		    		iph.GetSourceIP(source);
		    		ICMPPacket error(source, DESTINATION_UNREACHABLE,PORT_UNREACHABLE,p);
		    		MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to host"));
		    		MinetSend(mux,error);
		    	}
		    }

		    if (event.handle == sock) 
		    {
				// socket request or response has arrived
		    	
		    }
		}

		if (event.eventtype == MinetEvent::Timeout) 
		{
		    // timeout ! probably need to resend some packets
		}

    }

    MinetDeinit();

    return 0;
}
