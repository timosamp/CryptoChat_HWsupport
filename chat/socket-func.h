/*
 * socket-func.h
 *
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#ifndef _SOCKET_FUNC_H
#define _SOCKET_FUNC_H
int create_main_socket(int is_server);
int accept_connection(int sd);
int make_connection(char *hostname, int port);
#endif 

