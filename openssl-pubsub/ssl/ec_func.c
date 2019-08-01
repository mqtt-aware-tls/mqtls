#include "ec_func.h"

int make_keypair(struct keypair **pair, EC_GROUP *group, BN_CTX *ctx) {
  fstart("pair: %p, group: %p, ctx: %p", pair, group, ctx);
  BIGNUM *n = BN_new();
  EC_GROUP_get_order(group, n, ctx);

  (*pair) = (struct keypair *)malloc(sizeof(struct keypair));
  (*pair)->pri = BN_new();
  (*pair)->pub = EC_POINT_new(group);

  BN_rand_range((*pair)->pri, n); //private key
  EC_POINT_mul(group, (*pair)->pub, (*pair)->pri, NULL, NULL, ctx); //public key
  BIGNUM *x, *y;
  x = BN_new();
  y = BN_new();
  EC_POINT_get_affine_coordinates_GFp(group, (*pair)->pub, x, y, ctx);

  fend();
  return SUCCESS;
}

int char_to_pub(unsigned char *input, int key_length, EC_POINT *pubkey, EC_GROUP *group, BN_CTX *ctx)
{
  fstart("input: %p, key_length: %d, pubkey: %p, group: %p, ctx: %p", 
      input, key_length, pubkey, group, ctx);
  int ret;
  ret = EC_POINT_oct2point(group, pubkey, input, key_length, ctx);
  fend();
  return SUCCESS;
}

int pub_to_char(EC_POINT *secret, unsigned char **secret_str, int *slen, EC_GROUP *group, BN_CTX *ctx)
{
  fstart("secret: %p, secret_str: %p, slen: %p, group: %p, ctx: %p", 
      secret, secret_str, slen, group, ctx);
  int key_bytes;

  if (EC_GROUP_get_curve_name(group) == NID_X9_62_prime256v1)
    key_bytes = 256 / 8;
  else
    return FAILURE;

	*slen = 2 * key_bytes + 1;
  (*secret_str) = (unsigned char *)malloc(*slen);
  EC_POINT_point2oct(group, secret, POINT_CONVERSION_UNCOMPRESSED, (*secret_str), (*slen), ctx);

  fend();
	return SUCCESS;
}

