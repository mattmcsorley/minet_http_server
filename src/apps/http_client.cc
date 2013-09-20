#include "minet_socket.h"
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#define BUFSIZE 1024
#define MAX_LINE 1024
int main(int argc, char * argv[]) {

    char * server_name = NULL;
    int server_port    = -1;
    char * server_path = NULL;
    char * req         = NULL;
    bool ok            = false;
    
    int s, len, res;
    char buf[MAX_LINE];
    struct hostent *host_addr;
    struct sockaddr_in server_socket;
    
    /*parse args */
    if (argc != 5) {
	fprintf(stderr, "usage: http_client k|u server port path\n");
	exit(-1);
    }

    server_name = argv[2];
    server_port = atoi(argv[3]);
    server_path = argv[4];
    //printf("%s , %d, %s" , server_name, server_port , server_path);
    req = (char *)malloc(strlen("GET  HTTP/1.0\r\n\r\n") 
			 + strlen(server_path) + 1);  

    /* initialize */
    if (toupper(*(argv[1])) == 'K') { 
	minet_init(MINET_KERNEL);
    } else if (toupper(*(argv[1])) == 'U') { 
	minet_init(MINET_USER);
    } else {
	fprintf(stderr, "First argument must be k or u\n");
	exit(-1);
    }

    /* make socket */

    if((s = minet_socket(SOCK_STREAM)) < 0){
        minet_perror("Socket Not Created");
    }
    

    /* get host IP address  */
    /* Hint: use gethostbyname() */
    if ((host_addr = gethostbyname(server_name)) == NULL){
        minet_perror("Host not found");
    }


    /* set address */
    
    
    /* connect to the server socket */
   
    memcpy(&server_socket.sin_addr, host_addr->h_addr_list[0], host_addr->h_length);
     server_socket.sin_family = AF_INET;
    server_socket.sin_port = htons(server_port);
    
    if(minet_connect(s, &server_socket) < 0){
        minet_perror("Could not connect");
    }

    /* send request message */
    sprintf(req, "GET %s HTTP/1.0\r\n\r\n", server_path);
    printf("req %s" , req);
    /* wait till socket can be read. */
    /* Hint: use select(), and ignore timeout for now. */

    if ((res = minet_write(s, req, 1024)) <= 0)
    {
        minet_perror("Could not write");
    }
    
	
    /* first read loop -- read headers */
    if ((res = minet_read(s, buf, sizeof(buf)-1) <= 0)){
        minet_perror("Could not read");
    }

	while(res = minet_read(s, buf, sizeof(buf)-1) > 0)
	{
		printf("%s", buf);
	}

    close(s);

    /* examine return code */   

    //Skip "HTTP/1.0"
    //remove the '\0'

    // Normal reply has return code 200

    /* print first part of response: header, error code, etc. */

    /* second read loop -- print out the rest of the response: real web content */

    /*close socket and deinitialize */

    if (ok) {
	return 0;
    } else {
	return -1;
    }
}
