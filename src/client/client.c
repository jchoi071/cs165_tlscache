#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>

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
static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s ipaddress portnumber\n", __progname);
	exit(1);
}


static u_short hash(char *filename)
{
	size_t size = strlen(filename);
	char temp[size + 5];
	char proxyName[5];
	char hash[20];
	proxyName[4] = 0;
	strlcpy(temp, filename, size + 1);
	u_short proxies[6] = {9000, 9001, 9002, 9003, 9004, 9005};
	int sumHash;
	int highestHash = 0;
	u_short highestProxy = 0;
	for (unsigned int i = 0; i < 6; ++i)
	{
		sumHash = 0;
		temp[size] = 0;
		snprintf(proxyName, 5, "%i", proxies[i]);
		strlcat(temp, proxyName, size + 5);
		SHA1(temp, strlen(temp) + 1, hash);
		for (unsigned int j = 0; j < 20; ++j)
		{
			sumHash += hash[j];
		}
		
		if (sumHash > highestHash)
		{
			highestHash = sumHash;
			highestProxy = proxies[i];
		}

	}
	printf("Highest hash value: %i\n", highestHash);
	printf("Proxy to use: %i\n", highestProxy);
	return highestProxy;
}

int main(int argc, char *argv[])
{
	struct sockaddr_in server_sa;
	char buffer[80], *ep;
	size_t maxread;
	ssize_t r, rc;
	u_short port;
	u_long p;
	int sd, i;
	struct tls_config *tls_cfg = NULL;
	struct tls *tls_ctx = NULL;
	
	printf("Enter a filename (up to 80 characters): ");
	gets(buffer);
	
	port = hash(buffer);
	
	/*
	if (argc != 3)
		usage();

        p = strtoul(argv[2], &ep, 10);
        if (*argv[2] == '\0' || *ep != '\0') {
		// parameter wasn't a number, or was empty
		fprintf(stderr, "%s - not a number\n", argv[2]);
		usage();
	}
        if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		 
		 /*
		fprintf(stderr, "%s - value out of range\n", argv[2]);
		usage();
	}
	// now safe to do this
	port = p;
	*/

	/* set up TLS */
	if (tls_init() == -1)
		errx(1, "unable to initialize TLS");
	if ((tls_cfg = tls_config_new()) == NULL)
		errx(1, "unable to allocate TLS config");
	if (tls_config_set_ca_file(tls_cfg, "../../certificates/root.pem") == -1)
		errx(1, "unable to set root CA file");

	/*
	 * first set up "server_sa" to be the location of the server
	 */
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = inet_addr(argv[1]);
	if (server_sa.sin_addr.s_addr == INADDR_NONE) {
		fprintf(stderr, "Invalid IP address %s\n", argv[1]);
		usage();
	}

	/* ok now get a socket. */
	if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed");

	/* connect the socket to the server described in "server_sa" */
	if (connect(sd, (struct sockaddr *)&server_sa, sizeof(server_sa)) == -1)
		err(1, "connect failed");

	if ((tls_ctx = tls_client()) == NULL)
		errx(1, "tls client creation failed");
	if (tls_configure(tls_ctx, tls_cfg) == -1)
		errx(1, "tls configuration failed (%s)", tls_error(tls_ctx));
	if (tls_connect_socket(tls_ctx, sd, "localhost") == -1)
		errx(1, "tls connection failed (%s)", tls_error(tls_ctx));


	do {
		if ((i = tls_handshake(tls_ctx)) == -1)
			errx(1, "tls handshake failed (%s)", tls_error(tls_ctx));
	} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);

	/*
	 * finally, we are connected. find out what magnificent wisdom
	 * our server is going to send to us - since we really don't know
	 * how much data the server could send to us, we have decided
	 * we'll stop reading when either our buffer is full, or when
	 * we get an end of file condition from the read when we read
	 * 0 bytes - which means that we pretty much assume the server
	 * is going to send us an entire message, then close the connection
	 * to us, so that we see an end-of-file condition on the read.
	 *
	 * we also make sure we handle EINTR in case we got interrupted
	 * by a signal.
	 */
	
	ssize_t written, w;
	w = 0;
	written = 0;
	while (written < strlen(buffer)) {
		w = tls_write(tls_ctx, buffer + written,
		    strlen(buffer) - written);

		if (w == TLS_WANT_POLLIN || w == TLS_WANT_POLLOUT)
			continue;

		if (w < 0) {
			errx(1, "TLS write failed (%s)", tls_error(tls_ctx));
		}
		else
			written += w;
	}
	i = 0;
	do {
		i = tls_close(tls_ctx);
	} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
	
	r = -1;
	rc = 0;
	maxread = sizeof(buffer) - 1; /* leave room for a 0 byte */
	while ((r != 0) && rc < maxread) {
		r = tls_read(tls_ctx, buffer + rc, maxread - rc);
		if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
			continue;
		if (r < 0) {
			err(1, "tls_read failed (%s)", tls_error(tls_ctx));
		} else
			rc += r;
	}
	/*
	 * we must make absolutely sure buffer has a terminating 0 byte
	 * if we are to use it as a C string
	 */
	buffer[rc] = '\0';

	printf("Server sent:  %s",buffer);
	
	close(sd);
	return(0);
}
