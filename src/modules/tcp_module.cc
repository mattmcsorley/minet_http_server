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
	unsigned int our_seq_num;
	unsigned int our_ack_num;
	unsigned char flags;
	unsigned short sourcePort;
	unsigned short destPort;
	unsigned short winSize;
	unsigned char ipHeaderLen;
	unsigned char protocol;
	IPAddress sourceIP;
	IPAddress destIP;
	unsigned short ipLen;
	Buffer payload;
	Buffer recvd;
	int ackOffset;
	//Buffer returnBuffer;


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
	//printf("TCP receive\n");
	IPHeader iph;
	TCPHeader tcph;
	//cout << "PACKET " << p << endl;
	tcph = p.FindHeader(Headers::TCPHeader);
	tcph.GetSeqNum(seq_num);
	tcph.GetAckNum(ack_num);
	tcph.GetFlags(flags);
	//cout << tcph << endl;
	tcph.GetSourcePort(this->sourcePort);
	tcph.GetDestPort(this->destPort);
	//cout << "dest port: " << destPort << ", source port: " << sourcePort << endl;
	tcph.GetWinSize(winSize);

	//cout << tcph << endl;
	iph=p.FindHeader(Headers::IPHeader);
	iph.GetSourceIP(sourceIP);
	iph.GetDestIP(destIP);
	iph.GetTotalLength(ipLen);
	iph.GetProtocol(protocol);
	iph.GetHeaderLength(ipHeaderLen);

	//Extract payload
	cout << "Payload to be extracted: " << p.GetPayload() << endl; 
	payload.AddBack(p.GetPayload());
	
	
	state->receive(mux,sock);
}
void TCP::send(Buffer* buf, MinetHandle* mux){
	// send data packet 
	cout << "TCP::send()" << endl;

	IPHeader iph;
	TCPHeader tcph;
	unsigned char outgoing_flags = 0;
	//Packet outgoing_packet(*buff);
	Packet outgoing_packet(*buf);
	our_seq_num += (*buf).GetSize();
	iph.SetProtocol(protocol);
	iph.SetSourceIP(destIP);
	iph.SetDestIP(sourceIP);
	iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH + (*buf).GetSize());
	//iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
	outgoing_packet.PushFrontHeader(iph);

	tcph.SetSourcePort(destPort,outgoing_packet);
    tcph.SetDestPort(sourcePort,outgoing_packet);
    //SET_ACK(outgoing_flags);
    SET_PSH(outgoing_flags);
    tcph.SetFlags(outgoing_flags,outgoing_packet);
    //cout << "Setting seq_num to : " << outer->ack_num << endl;
    //cout << "Setting ack_num to : " << outer->seq_num + 1 << endl;
    tcph.SetSeqNum(ack_num,outgoing_packet);  
    //tcph.SetAckNum(seq_num + 1,outgoing_packet);    
    tcph.SetWinSize(winSize,outgoing_packet);
    tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH,outgoing_packet);
    outgoing_packet.PushBackHeader(tcph);	

    cout << "Sending " << (*buf) << endl;
    MinetSend(*mux, outgoing_packet);

    ack_num += (*buf).GetSize();
}
void TCPState::receive(MinetHandle* mux, MinetHandle* sock){}
void TCPState::send(Buffer* buf, MinetHandle* mux){}

TCP::TCP()
{
		our_ack_num = 0;
		our_seq_num = 300;
		ackOffset = 0;
		state = new TCPStateListen(this);
		//printf("TCP constructor\n");
}

TCPState::TCPState(TCP * out)
{
		outer = out;
		//printf("TCPState Constructor\n");
}

TCPStateListen::TCPStateListen(TCP *out) : TCPState(out) {}
TCPStateSynRecv::TCPStateSynRecv(TCP *out) : TCPState(out) {}
TCPStateEstablished::TCPStateEstablished(TCP *out) : TCPState(out) {}
TCPStateSynSent::TCPStateSynSent(TCP *out) : TCPState(out) {}

void TCPStateSynSent::receive(MinetHandle* mux, MinetHandle* sock){
	
	//cout << "TCPStateSynSent::receive" << endl;
	unsigned char outgoing_flags = 0;
	//Buffer *buff = new Buffer("Hello" , 5);

	
	if(IS_SYN(outer->flags) && IS_ACK(outer->flags)){

		//Send an ack
		//cout << "IS_SYN & IS_ACK" << endl;
		IPHeader iph;
		TCPHeader tcph;
		//Packet outgoing_packet(*buff);
		Packet outgoing_packet;
		outer->our_ack_num = outer->seq_num + 1;
		outer->our_seq_num += 1;
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
        //cout << "Setting seq_num to : " << outer->ack_num << endl;
        //cout << "Setting ack_num to : " << outer->seq_num + 1 << endl;
        tcph.SetSeqNum(outer->our_seq_num,outgoing_packet);   
        tcph.SetAckNum(outer->our_ack_num,outgoing_packet);    
        tcph.SetWinSize(outer->winSize,outgoing_packet);
        tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH,outgoing_packet);
        outgoing_packet.PushBackHeader(tcph);		

        MinetSend(*mux, outgoing_packet);
        

        Connection c(outer->destIP, outer->sourceIP, outer->destPort, outer->sourcePort, outer->protocol);
        Buffer empty;
        //cout << "In synSentState"<< c << endl;
        SockRequestResponse repl;
        repl.type=WRITE;
        repl.connection=c;
        repl.data=empty;
        repl.error=EOK;

        MinetSend(*sock, repl);

		outer->state = new TCPStateEstablished(outer);
	}

	//cout << "end of SynSentReceive" << endl;
}

void TCPStateEstablished::receive(MinetHandle* mux, MinetHandle* sock){
	cout << "TCPStateEstablished::receive" << endl;

	int temp = outer->ipLen - 20 - (outer->ipHeaderLen*4);
	if (temp > 0)
	{
		IPHeader iph;
		TCPHeader tcph;
		unsigned char outgoing_flags = 0;
		outer->our_ack_num += temp;
		//int ackOffset = outer->ipLen - 20 - (outer->ipHeaderLen*4);
		outer->ackOffset += temp;
		cout << "PAYLOAD " << outer->payload << endl;
		cout << "Ack Offset " << outer->ackOffset << endl;
		//Buffer extractedPayload = outer->payload.Extract(0, temp);
		//outer->extractedPayload.AddBack(outer->payload.Extract(0, temp));
		//returnBuffer.AddBack(extractedPayload);
		//outer->returnBuffer.AddBack(outer->payload.Extract(0, temp));
		//cout << "Return buffer: " << outer->returnBuffer << endl;
		//Packet outgoing_packet(outer->returnBuffer);
		Packet outgoing_packet;
		//cout << "Recieved: " << extractedPayload << endl;

		//Buffer payload = GetPayload();

		//cout << "Payload: " << payload << endl;

///////////////////////////////////////////////////
// Used to echo data back to tcp conntection
///////////////////////////////////////////////////
		iph.SetProtocol(outer->protocol);
		iph.SetSourceIP(outer->destIP);
		iph.SetDestIP(outer->sourceIP);
		//iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH + outer->returnBuffer.GetSize());
		iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
		outgoing_packet.PushFrontHeader(iph);

		tcph.SetSourcePort(outer->destPort,outgoing_packet);
	    tcph.SetDestPort(outer->sourcePort,outgoing_packet);
	    SET_ACK(outgoing_flags);
	    SET_PSH(outgoing_flags);
	    tcph.SetFlags(outgoing_flags,outgoing_packet);
	    //tcph.SetSeqNum(outer->ack_num,outgoing_packet);
	    tcph.SetSeqNum(outer->our_seq_num,outgoing_packet);
	    //tcph.SetAckNum(outer->seq_num + outer->ackOffset,outgoing_packet);
	    tcph.SetAckNum(outer->our_ack_num,outgoing_packet);


	    tcph.SetWinSize(outer->winSize,outgoing_packet);
	    tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH,outgoing_packet);
	    outgoing_packet.PushBackHeader(tcph);

	    MinetSend(*mux, outgoing_packet);


	    //Buffer toSock(outer->payload.Extract(0, temp);
	    Connection c(outer->destIP, outer->sourceIP, outer->destPort, outer->sourcePort, outer->protocol);
	    SockRequestResponse repl;
	    repl.type = WRITE;
	    repl.connection = c;
	    outer->recvd.AddBack(outer->payload);
	    //repl.data = outer->payload.Extract(0, outer->ackOffset);
	    repl.data = outer->payload;
	    repl.bytes = outer->payload.GetSize();
	    repl.error = EOK;

	    MinetSend(*sock, repl);

	    outer->payload = *(new Buffer());
	    outer->ackOffset = 0;
	}
	else if (IS_ACK(outer->flags) && !IS_FIN(outer->flags))
	{
		//cout << "Resetting shit" << endl;

		//outer->payload = *(new Buffer());
	    //outer->ackOffset = 0;
		
		//outer->returnBuffer = *(new Buffer());
	}
	else if (IS_FIN(outer->flags) && IS_ACK(outer->flags))
	{
		//cout << "IS_FIN" << endl;
		IPHeader iph;
		TCPHeader tcph;
		//Packet outgoing_packet(*buff);
		Packet outgoing_packet;
		unsigned char outgoing_flags = 0;

		iph.SetProtocol(outer->protocol);
		iph.SetSourceIP(outer->destIP);
		iph.SetDestIP(outer->sourceIP);
		iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
		outgoing_packet.PushFrontHeader(iph);

		tcph.SetSourcePort(outer->destPort,outgoing_packet);
	    tcph.SetDestPort(outer->sourcePort,outgoing_packet);
	    SET_ACK(outgoing_flags);
	    tcph.SetFlags(outgoing_flags,outgoing_packet);
	    tcph.SetSeqNum(outer->ack_num,outgoing_packet);
	    tcph.SetAckNum(outer->seq_num + 1,outgoing_packet);
	    tcph.SetWinSize(outer->winSize,outgoing_packet);
	    tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH,outgoing_packet);
	    outgoing_packet.PushBackHeader(tcph);

	    MinetSend(*mux, outgoing_packet); 
	} 
}

void TCPStateSynRecv::receive(MinetHandle* mux, MinetHandle* sock)
{
	//cout << "Syn Receieved::recieve" << endl;
	if(IS_ACK(outer->flags))
	{
		//cout << "IS_ACK, sending connection to socket" << endl;
		Connection c(outer->destIP, outer->sourceIP, outer->destPort, outer->sourcePort, outer->protocol);
		
		SockRequestResponse repl;
		repl.type=WRITE;
		repl.connection=c;
		repl.bytes=0;
		repl.error=EOK;
		MinetSend(*sock,repl);
		
		outer->payload = *(new Buffer());
		outer->state = new TCPStateEstablished(outer);
	}
}

void TCPStateListen::receive(MinetHandle* mux, MinetHandle* sock)
{
	cout << "TCPStateListen::received" << endl;
	//printf("source test : %d\n", (*outer).sourcePort);
	//printf("dest test : %d\n", (*outer).destPort);
	unsigned char outgoing_flags = 0;

	if(IS_SYN(outer->flags))
	{
		cout << "RECEIVE -> IS_SYN" << endl;
		IPHeader iph;
		TCPHeader tcph;
		Packet outgoing_packet;

		outer->our_ack_num = outer->seq_num + 1;


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
        tcph.SetAckNum(outer->our_ack_num,outgoing_packet);    
        tcph.SetWinSize(outer->winSize,outgoing_packet);
        tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH,outgoing_packet);
        outgoing_packet.PushBackHeader(tcph);		

        MinetSend(*mux, outgoing_packet);
        //sleep(3);
        MinetSend(*mux, outgoing_packet);
		outer->state = new TCPStateSynRecv(outer);
		//ret_val = &(outer->outgoing_packet);
	}

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
    ConnectionList<TCP *> dummyList;

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
    TCPStateListen listenState(&initState);
    //TCPStateListen listenState;
    TCPStateSynSent synSentState(&initState);

    while (MinetGetNextEvent(event, timeout) == 0) 
    {

		if ((event.eventtype == MinetEvent::Dataflow) && (event.direction == MinetEvent::IN)) 
		{
		
		    if (event.handle == mux) 
		    {
				// ip packet has arrived!
		    	//printf("MUXXXXX \n");
		    	Packet p;
		    	unsigned char header_len;
		    	bool checksumok;
		    	TCPHeader tcph;
		    	IPHeader iph;
				unsigned char flags;

		    	MinetReceive(mux,p);
		    	//cout << "PACKET RECEIVE " << p << endl; 
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
				tcph.GetFlags(flags);
				
				if( clist.FindMatching(c) == clist.end() )
				{
					//cout << "NOT FOUND" << endl;
					Connection dummy;
		
 					tcph.GetDestPort(dummy.srcport);
					iph.GetDestIP(dummy.src);
					iph.GetProtocol(dummy.protocol);
					//cout << dummy << endl;

					if ( dummyList.FindMatching(dummy) != dummyList.end() ){
						//cout << "FOUND IN DUMMYLIST" << endl;

						if( IS_SYN(flags) && !IS_ACK(flags) )
						{
							//cout << "IS_SYN" << endl; 
							initState = *(new TCP());	
							//TCPStateListen listenState(&initState);
							listenState = *(new TCPStateListen(&initState));
							initState.state = &listenState;
							addConnection(&clist, &c, &initState);
						}	
					}
					else
					{
						//cout << "NOT FOUND IN DUMMYLIST" << endl;
					}
				}
				
				ConnectionList<TCP *>::iterator cs = clist.FindMatching(c);


		    	if(cs != clist.end()) 
		    	{
		    		//cout << "RECEIVE" << endl;
		    		(*cs).state->receive(p, &mux, &sock);
		    	}
		    	else
		    	{
		    		//printf("cs ELSE\n");
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
						tcph.SetSeqNum(300,outgoing_packet);     
						tcph.SetWinSize(5840,outgoing_packet);
						tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH,outgoing_packet);
						outgoing_packet.PushBackHeader(tcph);		
						addConnection(&clist, &c, &initState);
						
						MinetSend(mux, outgoing_packet);
						sleep(3);
						MinetSend(mux, outgoing_packet);

						break;
		    		}
		    		case ACCEPT:
		    		{
		    			cout << "ACCEPT" << endl;
		    			Connection c = req.connection;
		    			cout << c << endl;
    					
    					addConnection(&dummyList, &c, NULL);

		    			//initState.state = &listenState;

		    			SockRequestResponse repl;
		    			repl.type = STATUS;
		    			repl.connection = req.connection;
		    			repl.bytes = 0;
		    			repl.error = EOK;
		    			MinetSend(sock, repl);

		    			break;
		    		}
		    		case STATUS:
		    		{
		    			cout << "STATUS" << endl;

		    			ConnectionList<TCP *>::iterator cs = clist.FindMatching(req.connection);

		    			if(cs != clist.end()) 
		    			{
		    				(*cs).state->recvd.ExtractFront(req.bytes);
		    				SockRequestResponse repl;
		    				if((*cs).state->recvd.GetSize() > 0){
				    			repl.type = WRITE;
				    			repl.data = (*cs).state->recvd;
				    			repl.connection = req.connection;
				    			repl.bytes = (*cs).state->recvd.GetSize();
				    			repl.error = EOK;
				    			MinetSend(sock, repl);		    					
		    				}

		    				cout << "Status complete" << endl;
		    			}
		    			break;
		    		}
		    		case WRITE:
		    		{
		    			cout << "WRITE" << endl;
		    			Buffer buffer = req.data;
		    			unsigned int bufferSize = buffer.GetSize();

		    			SockRequestResponse repl;
		    			repl.type = STATUS;
		    			repl.connection = req.connection;
		    			repl.bytes = bufferSize;
		    			repl.error = EOK;
			    		MinetSend(sock, repl);


		    			if (bufferSize > 0)
		    			{
		    				ConnectionList<TCP *>::iterator cs = clist.FindMatching(req.connection);

			    			if(cs != clist.end()) 
			    			{
			    				cout << "About to send..." << endl;
			    				(*cs).state->send(&buffer, &mux);
			    				cout << "Sent complete" << endl;
			    			}
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
