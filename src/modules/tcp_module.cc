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
#include <buffer.h>
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
	//Packet outgoing_packet;


	TCP();
	
	void receive(Packet p, MinetHandle* mux, MinetHandle* sock);
	void send(Buffer* buf, MinetHandle* mux);
};

struct TCPState 
{
    // need to write this
	TCP * outer;
	TCPState(TCP * out);

    virtual void send(Buffer* buf, MinetHandle* mux);
    virtual void receive(MinetHandle* mux, MinetHandle* sock);

    std::ostream & Print(std::ostream &os) const 
    { 
		os << "TCPState()"; 
		return os;
    }
};


struct TCPStateListen : TCPState
{
	TCPStateListen(TCP * out);
	void receive(MinetHandle* mux, MinetHandle* sock);
};


struct TCPStateEstablished : TCPState
{
	TCPStateEstablished(TCP * out);
	void receive(MinetHandle* mux, MinetHandle* sock);
	
};

struct TCPStateSynRecv : TCPState
{
	TCPStateSynRecv(TCP * out);
	void receive(MinetHandle* mux, MinetHandle* sock);
};

struct TCPStateSynSent : TCPState
{
	TCPStateSynSent(TCP * out);
	void receive(MinetHandle* mux, MinetHandle* sock);
};

void TCP::receive(Packet p, MinetHandle* mux, MinetHandle* sock){
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
	cout << "dest port: " << destPort << ", source port: " << sourcePort << endl;
	tcph.GetWinSize(winSize);

	//cout << tcph << endl;
	iph=p.FindHeader(Headers::IPHeader);
	iph.GetSourceIP(sourceIP);
	iph.GetDestIP(destIP);
	iph.GetTotalLength(ipLen);
	iph.GetProtocol(protocol);
	iph.GetHeaderLength(ipHeaderLen);

	
	
	state->receive(mux,sock);
}
void TCP::send(Buffer* buf, MinetHandle* mux){
	// send data packet 
	cout << "TCP::send()" << endl;
	//need to fill in.

}
void TCPState::receive(MinetHandle* mux, MinetHandle* sock){}
void TCPState::send(Buffer* buf, MinetHandle* mux){}
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
TCPStateEstablished::TCPStateEstablished(TCP *out) : TCPState(out) {}
TCPStateSynSent::TCPStateSynSent(TCP *out) : TCPState(out) {}

void TCPStateSynSent::receive(MinetHandle* mux, MinetHandle* sock){
	
	cout << "TCPStateSynSent::receive" << endl;
	unsigned char outgoing_flags = 0;
	//Buffer *buff = new Buffer("Hello" , 5);

	
	if(IS_SYN(outer->flags) && IS_ACK(outer->flags)){

		//Send an ack
		cout << "IS_SYN & IS_ACK" << endl;
		IPHeader iph;
		TCPHeader tcph;
		//Packet outgoing_packet(*buff);
		Packet outgoing_packet;

		iph.SetProtocol(outer->protocol);
		iph.SetSourceIP(outer->destIP);
		iph.SetDestIP(outer->sourceIP);
		//iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH + (*buff).GetSize());
		iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
		outgoing_packet.PushFrontHeader(iph);

		tcph.SetSourcePort(outer->destPort,outgoing_packet);
        tcph.SetDestPort(outer->sourcePort,outgoing_packet);
        SET_ACK(outgoing_flags);
        tcph.SetFlags(outgoing_flags,outgoing_packet);
        cout << "Setting seq_num to : " << outer->ack_num << endl;
        cout << "Setting ack_num to : " << outer->seq_num + 1 << endl;
        tcph.SetSeqNum(outer->ack_num,outgoing_packet);   
        tcph.SetAckNum(outer->seq_num + 1,outgoing_packet);    
        tcph.SetWinSize(outer->winSize,outgoing_packet);
        tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH,outgoing_packet);
        outgoing_packet.PushBackHeader(tcph);		

        MinetSend(*mux, outgoing_packet);
        

        Connection c(outer->destIP, outer->sourceIP, outer->destPort, outer->sourcePort, outer->protocol);
        Buffer empty;
        cout << "In synSentState"<< c << endl;
        SockRequestResponse repl;
        repl.type=WRITE;
        repl.connection=c;
        repl.data=empty;
        repl.error=EOK;

        MinetSend(*sock, repl);

		outer->state = new TCPStateEstablished(outer);
	}

	cout << "end of SynSentReceive" << endl;
}

void TCPStateEstablished::receive(MinetHandle* mux, MinetHandle* sock){
	cout << "TCPStateEstablished::receive" << endl;
}

void TCPStateSynRecv::receive(MinetHandle* mux, MinetHandle* sock)
{
	if(IS_ACK(outer->flags))
	{
		outer->state = new TCPStateEstablished(outer);
	}
}

void TCPStateListen::receive(MinetHandle* mux, MinetHandle* sock)
{
	printf("TCPStateListen received\n");
	printf("source test : %d\n", (*outer).sourcePort);
	printf("dest test : %d\n", (*outer).destPort);
	unsigned char outgoing_flags = 0;

	if(IS_SYN(outer->flags))
	{
		cout << "IS_SYN" << endl;
		IPHeader iph;
		TCPHeader tcph;
		Packet outgoing_packet;

		iph.SetProtocol(outer->protocol);
		iph.SetSourceIP(outer->destIP);
		iph.SetDestIP(outer->sourceIP);
		iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
		outgoing_packet.PushFrontHeader(iph);

		tcph.SetSourcePort(outer->destPort,outgoing_packet);
        tcph.SetDestPort(outer->sourcePort,outgoing_packet);
        SET_ACK(outgoing_flags);
        SET_SYN(outgoing_flags);
        tcph.SetFlags(outgoing_flags,outgoing_packet);  
        tcph.SetSeqNum(outer->ack_num,outgoing_packet);   
        tcph.SetAckNum(outer->seq_num + 1,outgoing_packet);    
        tcph.SetWinSize(outer->winSize,outgoing_packet);
        tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH,outgoing_packet);
        outgoing_packet.PushBackHeader(tcph);		

        MinetSend(*mux, outgoing_packet);
        //sleep(3);
        //MinetSend(*mux, outgoing_packet);
		outer->state = new TCPStateSynRecv(outer);
		//ret_val = &(outer->outgoing_packet);
	}

	cout << "Returning outgoing packet" << endl;
	//cout << "Recieve packet in right before return in ListenRecieve: " << ret_val << endl;
	//cout << "Dereferenced recieve packet in right before return in ListenRecieve: " << *ret_val << endl;
	//return ret_val;
}

void addConnection(ConnectionList<TCP *> *clist, Connection *c, TCP *initState)
{
	ConnectionToStateMapping<TCP *> * a = new ConnectionToStateMapping<TCP *>();
	Connection *conn = new Connection();
	conn->src = c->src;
	conn->dest = c->dest;
	conn->protocol = c->protocol;
	conn->srcport = c->srcport;
	conn->destport = c->destport;
	a->connection = *conn;
	a->state = initState; 
	clist->push_back(*a);
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


    TCP initState;
    TCPStateSynSent synSentState(&initState);
    TCPStateListen listenState(&initState);


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
		    	cout << "adding connection" << endl;
		    	addConnection(&clist, &c, &initState);
				/*ConnectionToStateMapping<TCP *> * a = new ConnectionToStateMapping<TCP *>();
				Connection *conn = new Connection();
				conn->src = c.src;
				conn->dest = c.dest;
				conn->protocol = c.protocol;
				conn->srcport = c.srcport;
				conn->destport = c.destport;
				a->connection = *conn;
				a->state = &initState; 
		    	clist.push_back(*a);*/

				ConnectionList<TCP *>::iterator cs = clist.FindMatching(c);


		    	if(cs != clist.end()) 
		    	{
		    		printf("cs\n");

		    		(*cs).state->receive(p, &mux, &sock);

	    			/*cout << "Sending in mux" << endl;
	    			cout << "Recieve packet in right before send: " << receive_packet << endl;
	    			cout << "Dereferenced recieve packet in right before send: " << *receive_packet << endl;

	    			cout << "Outgoing packet from TCP class: " << (*cs).state->outgoing_packet << endl;
	    			MinetSend(mux,(*cs).state->outgoing_packet);
	    			sleep(3);
	    			MinetSend(mux,(*cs).state->outgoing_packet);
	    			cout << "Sent" << endl;*/
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
		    	SockRequestResponse req;
		    	MinetReceive(sock, req);

		    	switch (req.type)
		    	{
		    		case CONNECT:
		    		{
		    			cout << "CONNECT" << endl;
					
						Connection c = req.connection;
						
						cout << "Intializing Client" << endl;
					    
					    initState.state = &synSentState;
		    			Buffer empty;
		    			SockRequestResponse repl;
		    			repl.type=STATUS;
	   					repl.connection=req.connection;
	    				repl.error=EOK;
	    				MinetSend(sock, repl);

						IPHeader iph;
						TCPHeader tcph;
						Packet outgoing_packet;

						unsigned char flags = 0;
						iph.SetProtocol(c.protocol);
						iph.SetSourceIP(c.src);
						iph.SetDestIP(c.dest);
						iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
						outgoing_packet.PushFrontHeader(iph);

						tcph.SetSourcePort(c.srcport,outgoing_packet);
					    tcph.SetDestPort(c.destport,outgoing_packet);
					    SET_SYN(flags);
					    tcph.SetFlags(flags,outgoing_packet);  
					    tcph.SetSeqNum(100,outgoing_packet);     
					    tcph.SetWinSize(5840,outgoing_packet);
					    tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH,outgoing_packet);
					    outgoing_packet.PushBackHeader(tcph);		

					    MinetSend(mux, outgoing_packet);
					    sleep(3);
					    MinetSend(mux, outgoing_packet);


		    			break;
		    		}
		    		case ACCEPT:
		    		{
		    			cout << "ACCEPT" << endl;
		    			initState.state = &listenState;
		    			break;
		    		}
		    		case STATUS:
		    		{
		    			cout << "STATUS" << endl;
		    			break;
		    		}
		    		case WRITE:
		    		{
		    			cout << "WRITE" << endl;
		    			Buffer buffer = req.data;

		    			ConnectionList<TCP *>::iterator cs = clist.FindMatching(req.connection);

		    			if(cs != clist.end()) 
		    			{
		    				printf("cs\n");

		    				(*cs).state->send(&buffer, &mux);
		    			}

		    			break;
		    		}
		    		case FORWARD:
		    		{
		    			cout << "FORWARD" << endl;
		    			break;
		    		}
		    		case CLOSE:
		    		{
		    			cout << "CLOSE" << endl;
		    			break;
		    		}
		    		default:
		    		{
		    			cout << "DEFAULT" << endl;
		    			break;
		    		}
		    	}

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
