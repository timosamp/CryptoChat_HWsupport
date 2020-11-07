/*
 * read_write.h
 *
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#ifndef _READ_WRITE_H
#define _READ_WRITE_H
ssize_t insist_read(int fd, const void *buf, size_t cnt);
ssize_t insist_write(int fd, const void *buf, size_t cnt);
int fill_urandom_buf(unsigned char *buf, size_t cnt);
size_t read_socket(int fdr, char *inbuf, size_t buf_size);
int read_write(int newsd, int cfd, unsigned char *key);
size_t read_socket(int fdr, char *inbuf, size_t buf_size);
void print_usage();
void read_argument_flags(int argc, char **argv, int *IS_SERVER, char *hostname, int *port);
#endif 

