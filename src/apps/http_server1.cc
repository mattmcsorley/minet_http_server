#include "minet_socket.h"
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <error.h>

#define BUFSIZE 1024
#define FILENAMESIZE 100


int handle_connection(int sock);
long get_file_size(FILE * f);

int main(int argc, char * argv[]) {
    int server_port = -1;
    int rc          =  0;
    int sock        = -1;
	int res, s, c, accepted_sock;
	struct sockaddr_in saddr;
	

    /* parse command line args */
    if (argc != 3) {
	fprintf(stderr, "usage: http_server1 k|u port\n");
	exit(-1);
    }
	minet_init(MINET_KERNEL);
    server_port = atoi(argv[2]);

    if (server_port < 1500) {
	fprintf(stderr, "INVALID PORT NUMBER: %d; can't be < 1500\n", server_port);
	exit(-1);
    }

    /* initialize and make socket */
	if((s = minet_socket(SOCK_STREAM)) < 0)
	{
        minet_perror("Socket Not Created");
		
    }

    /* set server address*/
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(server_port);
	
    /* bind listening socket */
	if (minet_bind(s, &saddr) < 0)
	{
		minet_perror("Socket could not bind");
	}

    /* start listening */
	if (minet_listen(s, 0) < 0)
	{
		minet_perror("Socket could not listen");
	}

    /* connection handling loop: wait to accept connection */
    while (1) 
	{
		/* handle connections */
		if ((accepted_sock = minet_accept(s, &saddr)) > 0)
		{
			rc = handle_connection(accepted_sock);
		}
    }
}

int handle_connection(int s) {
    bool ok = false;
	char buf[BUFSIZE];
	char filebuf[BUFSIZE];
	char filename[BUFSIZE];
	int res;

    char * ok_response_f = "HTTP/1.0 200 OK\r\n"	\
	"Content-type: text/plain\r\n"			\
	"Content-length: %d \r\n\r\n";
 
    char * notok_response = "HTTP/1.0 404 FILE NOT FOUND\r\n"	\
	"Content-type: text/html\r\n\r\n"			\
	"<html><body bgColor=black text=white>\n"		\
	"<h2>404 FILE NOT FOUND</h2>\n"
	"</body></html>\n";
    
    /* first read loop -- get request and headers*/
	res = minet_read(s, buf, sizeof(buf)-1);
	if (res > 0)
	{
		memset(filename, '\0', BUFSIZE);
		filename[0] = buf[4];
		int i = 5;
		int j = 1;
		while (buf[i] != 32)
		{
			filename[j] = buf[i];
			i++;
			j++;
		}
	}
	else
	{
		perror("Error during read");
	}
    
    /* parse request to get file name */
    /* Assumption: this is a GET request and filename contains no spaces*/

    /* try opening the file */
	FILE * fp;
	
	if ((fp = fopen(filename, "r")) == 0)
	{
		perror("File not opened");
		minet_write(s, notok_response, strlen(notok_response)*sizeof(char));
	}
	else
	{
		ok = true;
		long file_size = get_file_size(fp);
		char ok_response_buf[BUFSIZE];
		memset(ok_response_buf, '\0', BUFSIZE);
		sprintf(ok_response_buf, ok_response_f, file_size);
		/*printf("%s\n", ok_response_buf);
		printf("%d\n", sizeof(ok_response_buf));*/
		minet_write(s, ok_response_buf, strlen(ok_response_buf)*sizeof(char));
		//send(s, ok_response_buf, sizeof(ok_response_buf), 0);
		
		memset(filebuf, '\0', BUFSIZE);
		while(!feof(fp))
		{
			int num_read;

			num_read = fread(filebuf, 1, BUFSIZE, fp);
			minet_write(s, filebuf, num_read);
			//send(s, filebuf, num_read, 0);
			memset(filebuf, '\0', BUFSIZE);
		}
	}

    /* send response */
    if (ok) {
	/* send headers */
	
	/* send file */
	
    } else {
	// send error response
    }
    
    /* close socket and free space */
	minet_close(s);
  
    if (ok) {
	return 0;
    } else {
	return -1;
    }
}


long get_file_size(FILE * f)
{
	long size;
	
	fseek(f, 0, SEEK_END);
	
	size = ftell(f);
	
	fseek(f, 0, SEEK_SET);
	
	return size;
	
}