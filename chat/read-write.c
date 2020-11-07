#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "crypto.h"

#define BUFFER_SIZE 1024
#define ENCRYPTION_ENABLED 1

/* Insist until all of the data has been read */
ssize_t insist_read(int fd, void *buf, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = read(fd, buf, cnt);
                if (ret < 0)
                        return ret;
                buf += ret;
                cnt -= ret;
        }

        return orig_cnt;
}


/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int fill_urandom_buf(unsigned char *buf, size_t cnt)
{
        int crypto_fd;
        int ret = -1;

        crypto_fd = open("/dev/urandom", O_RDONLY);
        if (crypto_fd < 0)
                return crypto_fd;

        ret = insist_read(crypto_fd, buf, cnt);
        close(crypto_fd);

        return ret;
}

void print_usage() {
    printf("Usage: mychat-client ( server | client <hostname> <port> )\n");
}

/*
 * Set IS_SERVER, hostname, port flag depending on arguments
 */
void read_argument_flags(int argc, char **argv, int *IS_SERVER, char *hostname, int *port) {
    if (argc < 2 || argc > 4) {
        print_usage();
        exit(1);
    }
    if (!strcmp(argv[1], "server")) {
        if (argc != 2) {
            print_usage();
            exit(1);
        }
        *IS_SERVER = 1;
    } else if (!strcmp(argv[1], "client")) {
        if (argc != 4) {
            print_usage();
            exit(1);
        }
        *IS_SERVER = 0;
        strncpy(hostname, argv[2], strlen(argv[2]) + 1);
        *port = atoi(argv[3]);
    } else {
        print_usage();
        exit(1);
    }
    return;
}


/*
 * read up to BUFFER_SIZE characters from fdr and write to fdw
 * returns: actually read bytes
 */
size_t read_socket(int fdr, char *inbuf, size_t buf_size) {
    ssize_t rv;
    rv = read(fdr, inbuf, buf_size);
    if (rv == 0) {
        fprintf(stderr, "Connection closed.\n");
        return 0;    //shouldnt be rv < 0 if error ?.?.?
    } else if (rv < 0 && errno == EAGAIN) {
        fprintf(stderr, "Error, no data available, but shouldn't happen..\n");
        exit(1);
    } else if (rv < 0) {
        perror("Connection error");
        exit(1);
    }
    return rv;
}


/*
 * read once from terminal/socket and print correspondingly, while encrypting/decrypting
 */
int read_write(int newsd, int cfd, unsigned char *key) {

    fd_set rfds;
    struct timeval tv;
    int retval;
    char inbuf[BUFFER_SIZE];
    //char inbuf_socket[BUFFER_SIZE];

    tv.tv_sec = 5; //wait up to 2 seconds
    tv.tv_usec = 0;

    /* Wach fd's for available input */
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);
    FD_SET(newsd, &rfds);

    /* poll file descriptors to be available for read/write */
    retval = select(newsd + 1, &rfds, NULL, NULL, &tv);
    if (retval < 0) {
        perror("select");
    } else if (retval == 0) {
        return 0; //just no data yet..
    }

    if (FD_ISSET(0, &rfds)) {
//        printf("Will read from terminal...\n");
        size_t n = read_socket(0, inbuf, sizeof(inbuf));
//        printf("read %ld bytes\n", n);
        //fgets(inbuf, sizeof(inbuf), stdin);
        if (n < 0) {
            return -1;
        }
        //printf("[your_nickname]:  "); //would have to replace what the user typed.
        //fflush(stdout);
//        if (insist_write(1, inbuf, rv) != rv) {
//            perror("write to stdout failed");
//            return -1;
//        }
        if (ENCRYPTION_ENABLED) {
            unsigned char encrypted[BUFFER_SIZE];
            size_t new_n;
//            printf("will call crypto\n");
            new_n = crypto_operation(cfd, (unsigned char *)inbuf, encrypted, key, n, COP_ENCRYPT);
//            printf("will write to socket %ld bytes...\n", new_n);
            if (insist_write(newsd, encrypted, new_n) != new_n) {
                perror("write to remote peer failed");
                return -1;
            }
            //printf("returned from write\n");
        } else {
            if (insist_write(newsd, inbuf, n) != n) {
                perror("write to remote peer failed");
                return -1;
            }
        }
    }
    if (FD_ISSET(newsd, &rfds)) {
//        printf("enter read...\n");
        size_t n = read_socket(newsd, inbuf, sizeof(inbuf));
//        printf(" read %ld bytes->[start]", n);
//        for (int i=0; i< n; i ++) {
//            printf("%d ", inbuf[i]);
//        }
//        printf("[end]\n");
        if (n == 0) {
            return -1;
        }
        if (ENCRYPTION_ENABLED) {
            unsigned char decrypted[BUFFER_SIZE];
            size_t new_n = crypto_operation(cfd, (unsigned char*)inbuf, decrypted, key, n, COP_DECRYPT);
            if (new_n != n) {
                fprintf(stderr, "Error: Received data was not multiple of BLOCK_SIZE\n");
                exit(1);
            }
//            printf("will write to terminal %ld bytes->[start]", n);
//            for (int i=0; i< n; i ++) {
//                printf("%d ", decrypted[i]);
//            }
//            printf("[end]\n");
            insist_write(1, decrypted, n);
        } else {
            insist_write(1, inbuf, n);
        }
        //printf("[my_nickname]: "); //need fflush() !!!!!!!!!!!!!!!!!!!!!
        //fflush(stdout);
    }
    return 0;
}
