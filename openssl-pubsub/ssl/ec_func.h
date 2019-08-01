#ifndef __EC_FUNC_H__
#define __EC_FUNC_H__

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "logs.h"

int make_keypair(struct keypair **pair, EC_GROUP *group, BN_CTX *ctx);
int char_to_pub(unsigned char *input, int key_length, EC_POINT *pubkey, 
    EC_GROUP *group, BN_CTX *ctx);
int pub_to_char(EC_POINT *secret, unsigned char **secret_str, int *slen, 
    EC_GROUP *group, BN_CTX *ctx);

#endif /* __EC_FUNC_H__ */
