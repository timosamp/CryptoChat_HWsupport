/*
 * crypto.h
 *
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

#define DATA_SIZE       256
#define BLOCK_SIZE      16
#define KEY_SIZE	16  /* AES128 */

#define    COP_ENCRYPT    0
#define COP_DECRYPT    1
int crypto_operation(int cfd, unsigned char *src, unsigned char *dst, unsigned char *key, int data_len, int operation);
#endif 

