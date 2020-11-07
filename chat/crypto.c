/*
 * test_crypto.c
 * 
 * Performs a simple encryption-decryption 
 * of random data from /dev/urandom with the 
 * use of the cryptodev device.
 *
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
 
#include <sys/types.h>
#include <sys/stat.h>

#include <crypto/cryptodev.h>
#include "read-write.h"
#include "socket-common.h"
#include "crypto.h"

//#define DATA_SIZE       256
//#define BLOCK_SIZE      16
//#define KEY_SIZE	16  /* AES128 */
//
//#define    COP_ENCRYPT    0
//#define COP_DECRYPT    1



/*
 * ---Encrypt/Decrypt data---
 * cfd: file descriptor of crypto device
 * src: buffer containing input data to encrypt/decrypt (MUST be multiple of 16 bytes)
 * dst: buffer containing result data after function return.
 * key: key used for encryption/decryption (MUST be KEY_SIZE bytes)
 * length: length of data to be encrypted
 * operation: COP_ENCRYPT / COP_DECRYPT
 */
int crypto_operation(int cfd, unsigned char *src, unsigned char *dst, unsigned char *key, int data_len, int operation) {
    struct session_op sess;
    struct crypt_op cryp;
    unsigned char iv[BLOCK_SIZE];

    memset(&sess, 0, sizeof(sess));
    memset(&cryp, 0, sizeof(cryp));
    memcpy(iv, "hellohellohelloh", BLOCK_SIZE);

    /* Get crypto session for AES128 */
    /* FIXME: should assert key length */
    sess.cipher = CRYPTO_AES_CBC;
    sess.keylen = KEY_SIZE;
    sess.key = key;
    if (ioctl(cfd, CIOCGSESSION, &sess)) {
        perror("ioctl(CIOCGSESSION)");
        return 1;
    }

    /* Make sure data_len is a multiple of 16,
     * padding with 0' and updating the value */
    if (data_len % 16 != 0) {
        int to_pad = 16 - data_len % 16;
        memset(src + data_len, 0, to_pad);
        data_len += to_pad;
    }

    /* Perform crypto operation using established session*/
//    printf("Doing op=%d of %d bytes of data...", operation, data_len);
//    printf("\nData before:\n");
//    int i;
//    for (i = 0; i < data_len; i++) {
//        printf("%x", src[i]);
//    }
//    printf("\n");
    cryp.ses = sess.ses;
    cryp.len = data_len;
    cryp.src = src;
    cryp.dst = dst;
    cryp.iv = iv;
    cryp.op = operation;
    if (ioctl(cfd, CIOCCRYPT, &cryp)) {
        perror("ioctl(CIOCCRYPT)");
        return 1;
    }
    //printf("[OK]\n");

    /* Finish crypto session */
    if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
        perror("ioctl(CIOCFSESSION)");
        return 1;
    }

    memcpy(dst, cryp.dst, data_len);
//    printf("\nData after:\n");
//    for (i = 0; i < data_len; i++) {
//        printf("%x", dst[i]);
//    }
    return data_len;
}
