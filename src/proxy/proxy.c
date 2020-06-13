#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tls.h>
#include <openssl/sha.h>

struct FileCache
{
	char name[80];
	char *cache;
};

static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s -port portnumber -servername serverportnumber\n", __progname);
	exit(1);
}

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}


int main(int argc,  char *argv[])
{
	struct sockaddr_in sockname, client;
	char buffer[80], *ep, *sep;
	struct sigaction sa;
	int sd, i;
	socklen_t clientlen;
	u_short port, serverport;
	pid_t pid;
	u_long p, sp;
	struct tls_config *tls_cfg = NULL; // TLS config
	struct tls *tls_ctx = NULL; // TLS context
	struct tls *tls_cctx = NULL; // client's TLS context
	const int SIZE = 64; //512 bits
	char bloomFilter[SIZE];

	/*
	 * first, figure out what port we will listen on - it should
	 * be our first parameter.
	 */

	if (argc != 5) usage();
	
	errno = 0;
    p = strtoul(argv[2], &ep, 10);
    sp = strtoul(argv[4], &sep, 10);
    if (*argv[2] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[2]);
		usage();
	}
	
	else if (*argv[4] == '\0' || *sep != '\0') {
		fprintf(stderr, "%s - not a number\n", argv[4]);
		usage();
	}
	
    if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[2]);
		usage();
	}
	
	else if ((errno == ERANGE && sp == ULONG_MAX) || (sp > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[4]);
		usage();
	}
	/* now safe to do this */
	port = p;
	serverport = sp;

	/* set up TLS */
	if ((tls_cfg = tls_config_new()) == NULL)
		errx(1, "unable to allocate TLS config");
	if (tls_config_set_ca_file(tls_cfg, "../../certificates/root.pem") == -1)
		errx(1, "unable to set root CA file");
	if (tls_config_set_cert_file(tls_cfg, "../../certificates/proxy.crt") == -1) 
		errx(1, "unable to set TLS certificate file, error: (%s)", tls_config_error(tls_cfg));
	if (tls_config_set_key_file(tls_cfg, "../../certificates/proxy.key") == -1)
		errx(1, "unable to set TLS key file");
	if ((tls_ctx = tls_server()) == NULL)
		errx(1, "TLS server creation failed");
	if (tls_configure(tls_ctx, tls_cfg) == -1)
		errx(1, "TLS configuration failed (%s)", tls_error(tls_ctx));

	/* the message we send the client */
	//strlcpy(buffer,
	//    "It was the best of times, it was the worst of times... \n",
	//    sizeof(buffer));

	memset(&sockname, 0, sizeof(sockname));
	sockname.sin_family = AF_INET;
	sockname.sin_port = htons(port);
	sockname.sin_addr.s_addr = htonl(INADDR_ANY);
	sd=socket(AF_INET,SOCK_STREAM,0);
	if ( sd == -1)
		err(1, "socket failed");

	if (bind(sd, (struct sockaddr *) &sockname, sizeof(sockname)) == -1)
		err(1, "bind failed");

	if (listen(sd,3) == -1)
		err(1, "listen failed");

	/*
	 * we're now bound, and listening for connections on "sd" -
	 * each call to "accept" will return us a descriptor talking to
	 * a connected client
	 */


	/*
	 * first, let's make sure we can have children without leaving
	 * zombies around when they die - we can do this by catching
	 * SIGCHLD.
	 */
	sa.sa_handler = kidhandler;
        sigemptyset(&sa.sa_mask);
	/*
	 * we want to allow system calls like accept to be restarted if they
	 * get interrupted by a SIGCHLD
	 */
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == -1)
                err(1, "sigaction failed");

	/*
	 * finally - the main loop.  accept connections and deal with 'em
	 */
	printf("Proxy up and listening for connections on port %u\n", port);
	for(;;) {
		int clientsd;
		clientlen = sizeof(&client);
		clientsd = accept(sd, (struct sockaddr *)&client, &clientlen);
		if (clientsd == -1)
			err(1, "accept failed");
		/*
		 * We fork child to deal with each connection, this way more
		 * than one client can connect to us and get served at any one
		 * time.
		 */

/*
		pid = fork();
		if (pid == -1)
		     err(1, "fork failed");

		if(pid == 0) {
		*/
		ssize_t written, w;
		i = 0;
		if (tls_accept_socket(tls_ctx, &tls_cctx, clientsd) == -1)
			errx(1, "tls accept failed (%s)", tls_error(tls_ctx));
		else {
			do {
				if ((i = tls_handshake(tls_cctx)) == -1)
					errx(1, "tls handshake failed (%s)", tls_error(tls_ctx));
			} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
		}
		
		
		ssize_t r, rc;
		size_t maxread;

		strlcpy(buffer,
		    "                                                                                ",
		    sizeof(buffer));


		//read filename from client
		r = -1;
		rc = 0;
		maxread = sizeof(buffer) - 1; /* leave room for a 0 byte */
		while ((r != 0) && rc < maxread) {
			r = tls_read(tls_cctx, buffer + rc, maxread - rc);
			if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
				continue;
			if (r < 0) {
				err(1, "tls_read failed (%s)", tls_error(tls_cctx));
			} else
				rc += r;
		}
		/*
		 * we must make absolutely sure buffer has a terminating 0 byte
		 * if we are to use it as a C string
		 */
		buffer[rc] = '\0';
		
		// connect as client to the server
		
		struct sockaddr_in server_sa;
		struct tls_config *tls_cfg_s = NULL;
		struct tls *tls_ctx_s = NULL;
		int serversd, j;
		char localhost[] = "127.0.0.1";
		
		if ((tls_cfg_s = tls_config_new()) == NULL)
			errx(1, "unable to allocate TLS config");
		if (tls_config_set_ca_file(tls_cfg_s, "../../certificates/root.pem") == -1)
			errx(1, "unable to set root CA file");
		
		memset(&server_sa, 0, sizeof(server_sa));
		server_sa.sin_family = AF_INET;
		server_sa.sin_port = htons(serverport);
		server_sa.sin_addr.s_addr = inet_addr(localhost);
		if (server_sa.sin_addr.s_addr == INADDR_NONE) {
			fprintf(stderr, "Invalid IP address %s\n", localhost);
			usage();
		}

		/* ok now get a socket. */
		if ((serversd=socket(AF_INET,SOCK_STREAM,0)) == -1)
			err(1, "socket failed");

		/* connect the socket to the server described in "server_sa" */
		if (connect(serversd, (struct sockaddr *)&server_sa, sizeof(server_sa)) == -1)
			err(1, "connect failed");

		if ((tls_ctx_s = tls_client()) == NULL)
			errx(1, "tls client creation failed");
		if (tls_configure(tls_ctx_s, tls_cfg_s) == -1)
			errx(1, "tls configuration failed (%s)", tls_error(tls_ctx_s));
		if (tls_connect_socket(tls_ctx_s, serversd, "localhost") == -1)
			errx(1, "tls connection failed (%s)", tls_error(tls_ctx_s));


		do {
			if ((j = tls_handshake(tls_ctx_s)) == -1)
				errx(1, "tls handshake failed (%s)", tls_error(tls_ctx_s));
		} while(j == TLS_WANT_POLLIN || j == TLS_WANT_POLLOUT);

		//Bloom filter
		char temp, found = 1;
		char hash[SIZE], match[SIZE]; 
		SHA512(buffer, sizeof(buffer), hash);

		for (int a = 0; a < SIZE; ++a)
		{
			match[a] = 0;
			temp = hash[a] & bloomFilter[a];
			if (temp == hash[a])
			{
				match[a] = 1;
			}
		}
		
		for (int b = 0; b < SIZE; ++b)
		{
			if (match[b] <= 0)
			{
				found = 0;
				break;
			}
		}
		
		if (found <= 0)
		{
			printf("Proxy %i: File %s not found in filter\n", port, buffer);
			
			READFILE:
			
			//send filename to server
			w = 0;
			written = 0;
			while (written < strlen(buffer)) {
				w = tls_write(tls_ctx_s, buffer + written,
					strlen(buffer) - written);
				struct sockaddr_in server_sa;
				if (w == TLS_WANT_POLLIN || w == TLS_WANT_POLLOUT)
					continue;

				if (w < 0) {
					errx(1, "TLS write failed (%s)", tls_error(tls_ctx_s));
				}
				else
					written += w;
			}
			i = 0;
			do {
				i = tls_close(tls_ctx_s);
			} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
			
			//get file size from server
			int size = 0;
			r = tls_read(tls_ctx_s, &size, sizeof(size));
			//printf("Proxy: size = %i\n", size);
			char fileBuffer[size];
			
			if (size > 0)
			{
				printf("Proxy %i: File %s exists, adding to filter\n", port, buffer);
				for (int c = 0; c < SIZE; ++c)
				{
					bloomFilter[c] = hash[c] | bloomFilter[c];
				}
				
				//read file from server
				r = -1;
				rc = 0;
				maxread = sizeof(fileBuffer) - 1;
				while ((r != 0) && rc < maxread) {
					r = tls_read(tls_ctx_s, fileBuffer + rc, maxread - rc);
					if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
						continue;
					if (r < 0) {
						err(1, "tls_read failed (%s)", tls_error(tls_ctx_s));
					} else
						rc += r;
				}
				
				//send file size to client
				w = tls_write(tls_cctx, &size, sizeof(size));
				
				//send file to client
				w = 0;
				written = 0;
				while (written < strlen(fileBuffer)) {
					w = tls_write(tls_cctx, fileBuffer + written,
						strlen(fileBuffer) - written);
					struct sockaddr_in server_sa;
					if (w == TLS_WANT_POLLIN || w == TLS_WANT_POLLOUT)
						continue;

					if (w < 0) {
						errx(1, "TLS write failed (%s)", tls_error(tls_cctx));
					}
					else
						written += w;
				}
			}
		}
		else
		{
			printf("Proxy %i: File %s found in filter\n", port, buffer);
			goto READFILE;
		}

		close(clientsd);

	}
	return (0);
}
