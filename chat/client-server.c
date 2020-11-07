/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <termio.h>


#include "socket-common.h"
#include "crypto.h"
#include "read-write.h"
#include "socket-func.h"

int IS_SERVER;

int main(int argc, char **argv) {
    int sd;
    char hostname[100];
    int port;
    unsigned char key[KEY_SIZE];

    read_argument_flags(argc, argv, &IS_SERVER, hostname, &port);

    /* Make sure a broken connection doesn't kill us */
    signal(SIGPIPE, SIG_IGN);

    /*
     * Main function depending on server/client
     */
    if (IS_SERVER) {
        //turn_off_echo(0); //must turn only after '\n' not always../
        sd = create_main_socket(IS_SERVER);
        /* Loop forever, accept()ing connections */
        for (;;) {
            int newsd, cfd;
            newsd = accept_connection(sd);
            memcpy(key, "hellohellohelloh", KEY_SIZE);

            /* Get crypto device and initialize structures used for encryption/decryption */
            cfd = open("/dev/cryptodev0", O_RDWR);
            if (cfd < 0) {
                perror("open(/dev/crypto)");
                exit(1);
            }

            /* We break out of the loop when the remote peer goes away */
            for (;;) {
                if (read_write(newsd, cfd, key) < 0)
                    break;
            }
            if (close(cfd) < 0) {
                perror("close");
                exit(1);
            }
            if (close(newsd) < 0) {
               perror("close");
               exit(1);
            }
        }
    } else {
        int newsd, cfd;
        /* Get crypto device and initialize structures used for encryption/decryption */
        cfd = open("/dev/crypto", O_RDWR);
        if (cfd < 0) {
            perror("open(/dev/crypto)");
            return 1;}

        newsd = make_connection(hostname, port);
        memcpy(key, "hellohellohelloh", KEY_SIZE);
        for (;;) {
            if (read_write(newsd, cfd, key) < 0)
                break;
        }

        if (close(cfd) < 0) {
            perror("close"); }
        if (close(newsd) < 0) {
            perror("close");
            exit(1); }
    }
    /* This will never happen */
    return 1;
}
