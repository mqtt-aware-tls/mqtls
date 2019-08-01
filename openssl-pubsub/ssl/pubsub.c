#include <unistd.h>
#include "ssl_locl.h"
#include "logs.h"
#include "ec_func.h"
#include <openssl/rand.h>
#include <openssl/pubsub.h>

// Inside SSL_CTX
struct ps_state_table_st *init_ps_state_table(void)
{
  fstart();
  struct ps_state_table_st *ret;
  ret = (struct ps_state_table_st *)malloc(sizeof(struct ps_state_table_st));
  memset(ret, 0x0, sizeof(struct ps_state_table_st));

  if (access(STATE_FILE, F_OK) != -1)
  {
    psdebug("%s does exist", STATE_FILE);
    load_ps_state_from_file(ret, STATE_FILE);
  }
  else
  {
    psdebug("%s does not exist", STATE_FILE);
  }

  fend();
  return ret;
err:
  return NULL;
}

// Inside SSL_CTX
void free_ps_state_table(SSL_CTX *ctx)
{
  fstart("ctx: %p", ctx);
  struct ps_state_table_st *table;
  struct ps_state_st *prev, *curr;

  table = ctx->table;

  if (table)
  {
    store_ps_state_to_file(table, STATE_FILE);
    curr = table->head;
    while (curr)
    {
      prev = curr;
      curr = curr->next;
      free_ps_state(prev);
    }
    table->num = -1;
    free(table);
    table = NULL;
  }
  
  fend();
  return SUCCESS;
}

void load_ps_state_from_file(struct ps_state_table_st *table, const char *fname)
{
  fstart("table: %p, fname: %s", table, fname);
  FILE *fp;
  int num, tlen, klen, sequence;
  size_t size, res;
  unsigned char *buf, *p;
  struct ps_state_st *ps_state;
  fp = fopen(fname, "r");
  fseek(fp, 0, SEEK_END);
  size = ftell(fp);
  rewind(fp);

  psdebug("file size: %ld", size);
  buf = (unsigned char *)malloc(size);
  res = fread(buf, 1, size, fp);

  p = buf;

  // # of ps_state_st (1 byte) 
  // || length of topic (2 bytes) || topic (tlen bytes)
  // || length of key (2 bytes) || key (klen bytes) (payload encryption key)
  // || sequence (4 bytes)

  num = *(p++);
  psdebug("# of ps_state_st: %d", num);
  table->num = num;

  while (num > 0)
  {
    ps_state = init_ps_state();

    n2s(p, tlen);
    ps_state->topic = (unsigned char *)malloc(tlen);
    memcpy(ps_state->topic, p, tlen);
    ps_state->tlen = tlen;
    p += tlen;
    psdebug("Topic: %s", ps_state->topic);

    n2s(p, klen);
    ps_state->key = (unsigned char *)malloc(klen);
    memcpy(ps_state->key, p, klen);
    ps_state->klen = klen;
    p += klen;
    psprint("Payload Encryption Key", ps_state->key, 0, ps_state->klen, 10);

    sequence = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    ps_state->sequence = sequence;
    p += 4;
    psdebug("Sequence: %d", sequence);

    add_ps_state_to_table(table, ps_state);

    num--;
    psdebug("# of ps_state_st left: %d", num);
  }

  fclose(fp);
  free(buf);
  fend();
}

int calculate_total_length(struct ps_state_table_st *table)
{
  fstart("table: %p", table);
  int ret;
  struct ps_state_st *ps_state;

  ret = 1;
  ps_state = table->head;
  while (ps_state)
  {
    ret += 2 + ps_state->tlen + 2 + ps_state->klen + 4;
    ps_state = ps_state->next;
  }

  fend("ret: %d", ret);
  return ret;
}

void store_ps_state_to_file(struct ps_state_table_st *table, const char *fname)
{
  fstart("table: %p, fname: %s", table, fname);
  FILE *fp;
  int len;
  unsigned char *buf, *p;
  struct ps_state_st *ps_state;
  
  if (table->num > 0)
  {
    len = calculate_total_length(table);
    buf = (unsigned char *)malloc(len);
    p = buf;

    // # of ps_state_st (1 byte) 
    // || length of topic (2 bytes) || topic (tlen bytes)
    // || length of key (2 bytes) || key (klen bytes) (payload encryption key)
    // || sequence (4 bytes)

    *(p++) = table->num;
    ps_state = table->head;

    while (ps_state)
    {
      // Topic
      s2n(ps_state->tlen, p);
      memcpy(p, ps_state->topic, ps_state->tlen);
      p += ps_state->tlen;

      // Payload Encryption Key
      s2n(ps_state->klen, p);
      memcpy(p, ps_state->key, ps_state->klen);
      p += ps_state->klen;

      p[0] = (ps_state->sequence >> 24) & 0xff;
      p[1] = (ps_state->sequence >> 16) & 0xff;
      p[2] = (ps_state->sequence >> 8) & 0xff;
      p[3] = ps_state->sequence & 0xff;
      p += 4;

      ps_state = ps_state->next;
    }

    fp = fopen(fname, "w");
    fwrite(buf, 1, len, fp);
    fclose(fp);
  }

  fend();
}

void print_ps_state_table(SSL *s)
{
  fstart("s: %p", s);
  int idx;
  struct ps_state_table_st *table;
  struct ps_state_st *ps_state;
  
  idx = 0;
  table = s->ctx->table;
  if (!table) goto err;
  ps_state = table->head;
  if (!ps_state) goto err;

  psdebug("Number of PS State: %d\n", table->num);
  while (ps_state)
  {
    psdebug("===== (Index: %d) =====", idx++);
    psdebug("Topic (%d bytes): %s", ps_state->tlen, ps_state->topic);
    psdebug("Key Length: %d", ps_state->klen);
    psdebug("=======================\n");
  }

  fend();
err:
  ferr();
}

struct ps_state_st *init_ps_state(void)
{
  fstart();
  struct ps_state_st *ret;
  ret = (struct ps_state_st *)malloc(sizeof(struct ps_state_st));
  if (!ret) goto err;
  memset(ret, 0x0, sizeof(struct ps_state_st));
  fend();
  return ret;
err:
  ferr();
  return NULL;
}

void free_ps_state(struct ps_state_st *state)
{
  fstart("state: %p", state);
  if (state)
  {
    if (state->key)
      free(state->key);
    state->key = NULL;
    state->klen = -1;
    if (state->topic)
      free(state->topic);
    state->topic = NULL;
    state->tlen = -1;
  }
  fend();
}

int add_ps_state_to_table(struct ps_state_table_st *table, 
    struct ps_state_st *ps_state)
{
  fstart("table: %p, table->head: %p, table->tail: %p, ps_state: %p", 
      table, table->head, table->tail, ps_state);

  if (!(table->head))
  {
    table->head = ps_state;
    table->tail = table->head;
  }
  else
  {
    table->tail->next = ps_state;
    table->tail = ps_state;
  }
  table->num++;

  fend("table: %p, table->num: %d, table->head: %p, table->tail: %p",
      table, table->num, table->head, table->tail);
  return SUCCESS;
}

struct ps_state_st *get_ps_state_from_table(SSL *s, unsigned char *topic, int tlen)
{
  fstart("s: %p, topic: %p, tlen: %d", s, topic, tlen);
  struct ps_state_st *state, *ret;
  state = s->ctx->table->head;
  psdebug("s->ctx->table: %p, s->ctx->table->head: %p", s->ctx->table, 
      s->ctx->table->head);

  ret = NULL;
  while (state)
  {
    psdebug("state: %p", state);
    if (state->tlen == tlen)
    {
      if (!strncmp(state->topic, topic, tlen))
      {
        ret = state;
        break;
      }
    }
    state = state->next;
  }

  fend("state: %p", state);
  return ret;
}

unsigned char *generate_payload_encryption_key(void)
{
  fstart();
  unsigned char *key;
  key = (unsigned char *)malloc(MAX_PAYLOAD_ENC_KEY_LEN);
  RAND_bytes(key, MAX_PAYLOAD_ENC_KEY_LEN);
  psprint("Generated Payload Encryption Key", key, 0, MAX_PAYLOAD_ENC_KEY_LEN, 10);
  fend("key: %p", key);
  return key;
}

struct ps_req_st *init_ps_req(unsigned char *key, int klen,
    unsigned char *secret, int slen)
{
  fstart();
  struct ps_req_st *ret;
  ret = (struct ps_req_st *)malloc(sizeof(struct ps_req_st));
  if (!ret) goto err;
  memset(ret, 0x0, sizeof(struct ps_req_st));

  ret->key = (unsigned char *)malloc(klen);
  if (!ret->key) goto err;
  memcpy(ret->key, key, klen);
  ret->klen = klen;

  ret->secret = (unsigned char *)malloc(slen);
  if (!ret->secret) goto err;
  memcpy(ret->secret, secret, slen);
  ret->slen = slen;

  fend("ret: %p", ret);
  return ret;
err:
  ferr();
  return NULL;
}

void free_ps_req(struct ps_req_st *req)
{
  fstart("req: %p", req);
  if (req)
  {
    if (req->key)
      free(req->key);
    req->key = NULL;
    req->klen = -1;
    if (req->secret)
      free(req->secret);
    req->secret = NULL;
    req->slen = -1;
  }
  fend();
}

int add_ps_req_to_ps_state(struct ps_state_st *state, struct ps_req_st *req)
{
  fstart("state: %p, req: %p", state, req);
  struct ps_req_st *head;
  head = state->head;
  req->next = head;
  state->head = req;
  state->rnum++;
  fend();
}

struct ps_req_st *get_ps_req_from_ps_state(struct ps_state_st *state)
{
  fstart("state: %p", state);
  struct ps_req_st *ret;
  ret = state->head;
  state->head = ret->next;
  state->rnum--;
  fend("ret: %p", ret);
  return ret;
}

int set_topic(SSL *s, unsigned char *topic, int tlen)
{
  fstart("s: %p, topic: %p, tlen: %d", s, topic, tlen);
  struct ps_state_st *ps_state;
  ps_state = get_ps_state_from_table(s, topic, tlen);

  if (!ps_state)
  {
    ps_state = init_ps_state();
    ps_state->topic = (unsigned char *)malloc(tlen);
    memcpy(ps_state->topic, topic, tlen);
    ps_state->tlen = tlen;
    add_ps_state_to_table(s->ctx->table, ps_state);
  }

  fend();
  return SUCCESS;
err:
  ferr();
  return FAILURE;
}

int set_topic_group_key(SSL *s, unsigned char *topic, int tlen, 
    unsigned char *key, int klen)
{
  fstart("s: %p, topic: %p, tlen: %d, key: %p, klen: %d", s, key, klen);
  struct ps_state_st *ps_state;
  ps_state = get_ps_state_from_table(s, topic, tlen);

  if (ps_state)
  {
    if (ps_state->key)
    {
      free(ps_state->key);
    }
  }
  else
  {
    ps_state = init_ps_state();
    ps_state->topic = (unsigned char *)malloc(tlen);
    memcpy(ps_state->topic, topic, tlen);
    ps_state->tlen = tlen;
    add_ps_state_to_table(s->ctx->table, ps_state);
  }
  ps_state->key = (unsigned char *)malloc(klen);
  memcpy(ps_state->key, key, klen);
  ps_state->klen = klen;

  fend();
  return SUCCESS;
err:
  ferr();
  return FAILURE;
}

int get_topic(SSL *s, unsigned char *topic, int *tlen)
{
  fstart("s: %p, topic: %p, tlen: %d", s, topic, tlen);
  struct ps_state_st *ps_state;
  ps_state = get_ps_state_from_table(s, topic, tlen);

  if (!ps_state) goto err;
  if (!ps_state->topic) goto err;
  topic = ps_state->topic;
  tlen = ps_state->tlen;

  fend();
  return SUCCESS;
err:
  ferr();
  return FAILURE;
}

int get_topic_group_key(SSL *s, unsigned char *topic, int tlen, 
    unsigned char *key, int *klen)
{
  fstart("s: %p, topic: %p, tlen: %d, key: %p, klen: %d", s, key, klen);
  struct ps_state_st *ps_state;
  ps_state = get_ps_state_from_table(s, topic, tlen);

  if (!ps_state) goto err;
  if (!(ps_state->key)) goto err;

  key = ps_state->key;
  *klen = ps_state->klen;

  fend();
  return SUCCESS;
err:
  ferr();
  return FAILURE;
}

int get_topic_group_sequence(SSL *s, unsigned char *topic, int tlen)
{
  fstart("s: %p, topic: %s, tlen: %d", s, topic, tlen);
  int ret;
  struct ps_state_st *ps_state;

  ps_state = get_ps_state_from_table(s, topic, tlen);
  if (!ps_state) goto err;

  fend();
  return ps_state->sequence;
err:
  ferr();
  return FAILURE;
}

int do_write_process_pubsub(SSL *s, void *buf, int *len)
{
  fstart("s: %p, buf: %p, len: %d", s, buf, *len);
  struct ps_state_st *ps_state;
  struct message_st *msg;

  ps_state = get_ps_state_from_table(s, s->topic, s->tlen);

  if (s->role == TLSPS_ROLE_PUBLISHER)
  {
    if (check_publish_message(buf, *len, TLSPS_POS_PUB_WRITE) > 0)
    {
      psdebug("This is a PUBLISH message");
      //encrypt_payload(s, buf, len);
      if (ps_state->rnum > 0)
      {
        send_payload_encryption_keys(s, buf, len, ps_state);
        psdebug("Length of the message after send_payload_encryption_keys: %d", *len);
      }
    }
  }
  else if (s->role == TLSPS_ROLE_BROKER)
  {
    if (check_publish_message(buf, *len, TLSPS_POS_BROKER_WRITE) > 0)
    {
      psdebug("This is a PUBLISH message");
      msg = get_key_material_from_queue(s);
      if (msg)
        forward_payload_encryption_key(s, buf, len, msg);
    }
  }

  fend("s: %p, buf: %p, len: %d", s, buf, *len);
  return SUCCESS;
}

int do_read_process_pubsub(SSL *s, void *buf, int *len)
{
  fstart("s: %p, buf: %p, len: %d", s, buf, *len);
  struct ps_state_st *ps_state = get_ps_state_from_table(s, s->topic, s->tlen);

  if (s->role == TLSPS_ROLE_SUBSCRIBER)
  {
    if (ps_state->klen == 0)
    {
      get_payload_encryption_key(s, buf, len);
    }
    //decrypt_payload(s, buf, len, ps_state);
  }
  else if (s->role == TLSPS_ROLE_BROKER)
  {
    store_payload_encryption_keys(s, buf, len);
  }

  fend("s: %p, buf: %p, len: %d", s, buf, *len);
  return SUCCESS;
}

int get_payload_encryption_key(SSL *s, void *buf, int *len)
{
  fstart("s: %p, buf: %p, len: %d", s, buf, *len);

  // offset (2 bytes) || klen (2 bytes) || key (= H(g^a)) (klen bytes)
  // || dhlen (2 bytes) || dh (dhlen bytes)
  // || ilen (2 bytes) || encrypted info (ilen bytes)
  //
  // info = sequence number (4 bytes) || payload encryption key (rest bytes)

  unsigned char plain[50];
  unsigned char sec[SHA256_DIGEST_LENGTH];
  unsigned char iv[SHA256_DIGEST_LENGTH] = {0, };
  unsigned char *p, *q, *pstr, *key, *dh, *info, *sig, *cert, *msg;
  int i, klen, dhlen, plen, slen, xlen, diff, ilen, mlen;
  int ret, offset, sequence, siglen, certlen;
  struct ps_state_st *ps_state;
  EC_GROUP *group;
  BN_CTX *ctx;
  BIGNUM *x, *y;
  EC_POINT *secret, *peer_pub;
  EVP_MD_CTX *md_ctx;
  EVP_CIPHER_CTX *cctx;
  EVP_PKEY *pubkey;
  X509 *x509;

  p = (unsigned char *)buf;
  n2s(p, offset);
  msg = p;
  mlen = 0;

  // H(g^a)
  n2s(p, klen);
  psdebug("Length of ID: %d", klen);
  if (klen != s->klen)
  {
    psdebug("Error: key mismatch: klen: %d, s->klen: %d", klen, s->klen);
  }
  else
  {
    if (strncmp(p, s->key, klen))
    {
      psdebug("Error: keymismatch");
    }
  }
  p += klen;

  // g^b
  group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  ctx = BN_CTX_new();
  x = BN_new();
  y = BN_new();
  secret = EC_POINT_new(group);
  peer_pub = EC_POINT_new(group);

  n2s(p, dhlen);
  psdebug("Length of DH pubkey: %d", dhlen);
  dh = p;
  p += dhlen;

  char_to_pub(dh, dhlen, peer_pub, group, ctx);
  psdebug("group: %p, secret: %p, peer_pub: %p, s->ecdhe->pri: %p, ctx: %p",
      group, secret, peer_pub, s->ecdhe->pri, ctx);
  EC_POINT_mul(group, secret, NULL, peer_pub, s->ecdhe->pri, ctx);
  EC_POINT_get_affine_coordinates_GFp(group, secret, x, y, ctx);
  slen = (klen - 1) / 2;
  xlen = BN_bn2bin(x, sec);

  if (xlen < slen)
  {
    diff = slen - xlen;

    for (i=slen-1; i>=diff; i--)
      sec[i] = sec[i-diff];

    for (i=diff-1; i>0; i--)
      sec[i] = 0;
  }

  // info
  n2s(p, ilen);
  psdebug("Length of info: %d", ilen);
  info = p;
  p += ilen;
  
  cctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(cctx, EVP_aes_128_gcm(), NULL, sec, iv);
  EVP_DecryptUpdate(cctx, plain, &plen, info, ilen);
  // EVP_DecryptFinal_ex(cctx, plain + plen, &plen);
  

  psprint("Received Cipher", info, 0, ilen, 10);
  psprint("Decrypted Info", plain, 0, plen, 10);

  q = plain;
  sequence = (q[0] << 24) | (q[1] << 16) | (q[2] << 8) | q[3];
  q += 4;
  psdebug("Sequence Number Received: %d", sequence);

  ps_state = get_ps_state_from_table(s, s->topic, s->tlen);
  ps_state->sequence = sequence;
  ps_state->klen = plen - 4;
  ps_state->key = (unsigned char *)malloc(ps_state->klen);
  memcpy(ps_state->key, q, ps_state->klen);
  add_ps_state_to_table(s->ctx->table, ps_state);
  
  psprint("Payload Encryption Key Received", ps_state->key, 0, ps_state->klen, 10);

  mlen = 2 + klen + 2 + dhlen + 2 + ilen;

  // signature
  n2s(p, siglen);
  sig = p;
  p += siglen;
  psprint("Signature", sig, 0, siglen, 10);

  // certificate
  n2s(p, certlen);
  cert = p;
  psdebug("before d2i_X509");
  x509 = d2i_X509(NULL, &cert, certlen);
  psdebug("before get pubkey");
  pubkey = X509_get_pubkey(x509);
  psdebug("after get pubkey");

  ret = verify_signature(msg, mlen, NID_sha256, siglen, sig, pubkey);
  psdebug("Verification Result: %d", ret);

  // buf should be increased and len should be decreased
  fend("buf: %p, len: %d", buf, *len);
  return SUCCESS;
}

int send_payload_encryption_keys(SSL *s, void *buf, int *len,
    struct ps_state_st *ps_state)
{
  fstart("s: %p, buf: %p, len: %d, ps_state: %p", s, buf, *len, ps_state);

  // offset (2 bytes) || # of reqs (1 byte) 
  // || klen (2 bytes) || key (= H(g^a)) (klen bytes)
  // || dhlen (2 bytes) || dh (dhlen bytes)
  // || ilen (2 bytes) || encrypted info (ilen bytes)
  // || siglen (2 bytes) || signature (siglen bytes)
  // || certlen (2 bytes) || certificate (certlen bytes)
  //
  // info = sequence number (4 bytes) || payload encryption key (rest bytes)

  unsigned char blk[2048], plain[50], cipher[50];
  unsigned char iv[SHA256_DIGEST_LENGTH] = {0, };
  unsigned char *p, *q, *pstr, *b, *sigblk, *init, *cbuf;
  int num, offset, plen, mlen, clen, sequence, siglen, certlen;
  EC_GROUP *group;
  BN_CTX *bn_ctx;
  EVP_CIPHER_CTX *ctx;
  EVP_PKEY *priv;
  struct ps_req_st *req;

  cbuf = NULL;
  group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  bn_ctx = BN_CTX_new();
  pub_to_char(s->ecdhe->pub, &pstr, &plen, group, bn_ctx);

  num = ps_state->rnum;
  p = blk;
  offset = 0;
  ps_state->sequence--;
  psdebug("# of reqs: %d, sequence: %d", num, ps_state->sequence);

  sequence = ps_state->sequence;
  q = plain;
  q[0] = (sequence >> 24) & 0xff;
  q[1] = (sequence >> 16) & 0xff;
  q[2] = (sequence >> 8) & 0xff;
  q[3] = sequence & 0xff;
  q += 4;
  memcpy(q, ps_state->key, ps_state->klen);

  psprint("payload encryption key", ps_state->key, 0, ps_state->klen, 10);
  mlen = 4 + ps_state->klen;

  if (s->cert)
  {
    psdebug("Certificate exists");
    priv = s->cert->key->privatekey;
    if (priv)
      psdebug("Privatekey exists");
    psdebug("s->ctx->x509: %p", s->ctx->x509);
    certlen = i2d_X509(s->ctx->x509, NULL);
    i2d_X509(s->ctx->x509, &cbuf);
  }

  *(p++) = num;
  offset += 1;

  while (num > 0)
  {
    init = p;
    req = get_ps_req_from_ps_state(ps_state);

    // H(g^a)
    psprint("H(g^a)", req->key, 0, req->klen, 10);
    s2n(req->klen, p);
    memcpy(p, req->key, req->klen);
    p += req->klen;
    offset += 2 + req->klen;

    // g^b
    psprint("g^b", pstr, 0, plen, 10);
    s2n(plen, p);
    memcpy(p, pstr, plen);
    p += plen;
    offset += 2 + plen;

    // info
    psprint("Plain", plain, 0, mlen, 10);
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, req->secret, iv);
    EVP_EncryptUpdate(ctx, cipher, &clen, plain, mlen);
    //EVP_EncryptFinal_ex(ctx, cipher + clen, &clen);
    EVP_CIPHER_CTX_free(ctx);
    s2n(clen, p);
    memcpy(p, cipher, clen);
    p += clen;
    offset += 2 + clen;
    psprint("Cipher", cipher, 0, clen, 10);

    make_signature_block(&sigblk, init, 2 + req->klen + 2 + plen + 2 + clen,
        priv, NID_sha256, &siglen);
    s2n(siglen, p);
    memcpy(p, sigblk, siglen);
    psprint("Signature", sigblk, 0, siglen, 10);
    p += siglen;
    offset += 2 + siglen;

    s2n(certlen, p);
    memcpy(p, cbuf, certlen);
    psprint("Certificate", cbuf, 0, certlen, 10);
    p += certlen;
    offset += 2 + certlen;

    num--;
  }

  memmove(buf + 1 + 2 + offset, buf, *len);
  memcpy(buf + 1 + 2, blk, offset);
  p = buf;
  *(p++) = 0xFF;
  psdebug("total offset: %d", offset);
  s2n(offset, p);
  *len = 1 + 2 + offset + *len;

  // buf should be same and len should be increased
  fend("buf: %p, len: %d", buf, *len);
  return SUCCESS;
}

int forward_payload_encryption_key(SSL *s, void *buf, int *len, struct message_st *msg)
{
  fstart("s: %p, buf: %p, len: %d, msg: %p", s, buf, *len, msg);
  int offset;
  unsigned char *p;

  memmove(buf + 1 + 2 + msg->mlen, buf, *len);
  memcpy(buf + 1 + 2, msg->msg, msg->mlen);
  p = buf;
  *(p++) = 0xFF;
  s2n(msg->mlen, p);

  *len += 1 + 2 + msg->mlen;

  fend();
  return SUCCESS;
}

int store_payload_encryption_keys(SSL *s, void *buf, int *len)
{
  fstart("s: %p, buf: %p, len: %d", s, buf, *len);
  unsigned char *p, *m, *key;
  int offset, num, mlen, klen, tmp;
  struct message_st *msg;

  p = (unsigned char *)buf;
  n2s(p, offset);
  psdebug("Offset: %d", offset);
  num = (*p++);
  psdebug("# of reqs: %d", num);

  while (num > 0)
  {
    mlen = 0;
    m = p;

    // key
    n2s(p, klen);
    key = p;
    p += klen;
    mlen += (2 + klen);

    // dh
    n2s(p, tmp);
    p += tmp;
    mlen += (2 + tmp);

    // info
    n2s(p, tmp);
    p += tmp;
    mlen += (2 + tmp);

    // signature
    n2s(p, tmp);
    p += tmp;
    mlen += (2 + tmp);

    // cert
    n2s(p, tmp);
    p += tmp;
    mlen += (2 + tmp);

    psdebug("Length of Message: %d", mlen);
    msg = init_message(s->topic, s->tlen, key, klen, m, mlen);
    add_message_to_queue(s, msg);
    num--;
  }

  fend();
  return SUCCESS;
}

int encrypt_payload(SSL *s, void *buf, int *len)
{
  fstart("s: %p, buf: %p, len: %d", s, buf, *len);
  unsigned char iv[SHA256_DIGEST_LENGTH] = {0, };
  unsigned char plain[256], ciph[256];
  unsigned char *p, *topic, *payload;
  struct ps_state_st *ps_state;
  int control, mlen, tlen, offset, plen, clen, diff;
  EVP_CIPHER_CTX *ctx;
  ps_state = get_ps_state_from_table(s, s->topic, s->tlen);
  p = (unsigned char *)buf;

  psprint("Message in Encrypt", p, 0, *len, 10);

  offset = 0;
  control = *(p++);
  offset++;
  psdebug("Control: %d", control);
  mlen = *(p++);
  offset++;
  psdebug("Message Length: %d", mlen);
  n2s(p, tlen);
  offset += 2;
  psdebug("Topic Length: %d", tlen);
  topic = p;
  p += tlen;
  offset += tlen;
  payload = p;
  plen = *len - offset;
  psdebug("Payload Length: %d", plen);

  p = plain;
  p[0] = (ps_state->sequence >> 24) & 0xff;
  p[1] = (ps_state->sequence >> 16) & 0xff;
  p[2] = (ps_state->sequence >> 8) & 0xff;
  p[3] = ps_state->sequence & 0xff;
  p += 4;

  psdebug("Sequence: %d", ps_state->sequence);
  ps_state->sequence++;
  memcpy(p, payload, plen);

  ctx = EVP_CIPHER_CTX_new();
  psprint("Payload Encryption Key", ps_state->key, 0, ps_state->klen, 10);
  EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, ps_state->key, iv);
  EVP_EncryptUpdate(ctx, ciph, &clen, plain, plen + 4);
  memcpy(payload, ciph, clen);
  diff = clen - plen;
  p = (unsigned char *)buf;
  p[1] = p[1] + diff;
  *len += diff;

  psprint("Encrypted", p, 0, *len, 10);

  EVP_CIPHER_CTX_cleanup(ctx);
  fend("buf: %p, len: %d", buf, *len);
  return SUCCESS;
}

int decrypt_payload(SSL *s, void *buf, int *len)
{
  fstart("s: %p, buf: %p, len: %d", s, buf, *len);
  unsigned char iv[SHA256_DIGEST_LENGTH] = {0, };
  unsigned char decrypted[256];
  unsigned char *p, *payload;
  struct ps_state_st *ps_state;
  int tlen, offset, plen, dlen, sequence, diff;
  EVP_CIPHER_CTX *ctx;
  ps_state = get_ps_state_from_table(s, s->topic, s->tlen);
  psdebug("ps_state: %p", ps_state);
  p = (unsigned char *)buf;

  psprint("Message in Decrypt", p, 0, *len, 10);

  offset = 0;
  n2s(p, tlen);
  offset += 2;
  p += tlen;
  offset += tlen;
  psdebug("Topic Length: %d", tlen);
  payload = p;
  plen = *len - offset;
  psprint("Payload", payload, 0, plen, 10);

  ctx = EVP_CIPHER_CTX_new();
  psprint("Payload Encryption Key", ps_state->key, 0, ps_state->klen, 10);
  EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, ps_state->key, iv);
  EVP_DecryptUpdate(ctx, decrypted, &dlen, payload, plen);

  p = decrypted;
  psprint("Decrypted", p, 0, dlen, 10);
  sequence = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
  psdebug("ps_state->sequence: %d, Sequence: %d", ps_state->sequence, sequence);
  if (ps_state->sequence == sequence)
  {
    psdebug("Right Sequence Number");
    ps_state->sequence++;
  }
  else
  {
    psdebug("Wrong Sequence Number");
  }
  
  p += 4;
  memcpy(payload, p, dlen - 4);
  diff = plen - (dlen - 4);

  EVP_CIPHER_CTX_cleanup(ctx);
  fend("buf: %p, len: %d", buf, *len);
  return SUCCESS;
}

int check_publish_message(void *buf, int len, int pos)
{
  fstart("buf: %p, len: %d", buf, len);
  int offset, num, ret;
  unsigned char *p;
  p = (unsigned char *)buf;

  if (pos == TLSPS_POS_SUB_READ || pos == TLSPS_POS_BROKER_READ)
  {
    n2s(p, offset);
    if (offset > len) goto err;
    p += offset;
    psdebug("offset: %d", offset);
  }

  if ((*p) == 0x30)
    ret = SUCCESS;
  else
    ret = FAILURE;

  if (ret == SUCCESS)
    psdebug("PUBLISH message!");
  else
    psdebug("Not PUBLISH message!");
  return ret;
err:
  return FAILURE;
}

int make_signature_block(unsigned char **sigblk, unsigned char *msg, int msg_len, EVP_PKEY *priv, int nid, int *sigblk_len)
{
	int rc, rc1, rc2;
	EVP_MD_CTX *ctx;
	unsigned char *sig, *p;
	size_t sig_len;

	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
	{
		//printf("EVP_MD_CTX_create failed\n");
		goto err;
	}

	// Initialize the md according to nid
	switch (nid)
	{
		case NID_sha256:
			rc1 = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
			rc2 = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv);
			break;
		default:
			//printf("Unknown Hash algorithm\n");
			goto err;
	}

	// Make the signature
	if (rc1 != 1)
	{
		//printf("PROGRESS: Digest Init Failed\n");
		goto err;
	}
	if (rc2 != 1)
	{
		//printf("PROGRESS: DigestSign Init Failed\n");
		goto err;
	}

	rc = EVP_DigestSignUpdate(ctx, msg, msg_len);
	if (rc != 1)
	{
		//printf("PROGRESS: DigestSign Update Failed\n");
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, NULL, &sig_len);
	if (rc != 1)
	{
		//printf("PROGRESS: DigestSign Final Failed\n");
		goto err;
	}
	sig = OPENSSL_malloc(sig_len);

	if (sig == NULL)
	{
		//printf("PROGRESS: OPENSSL_malloc error\n");
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, sig, &sig_len);
	if (rc != 1)
	{
		//printf("PROGRESS: DigestSign Final Failed\n");
		goto err;
	}

	*sigblk_len = sig_len;
	*sigblk = (unsigned char *)OPENSSL_malloc(*sigblk_len);
	p = *sigblk;
	memcpy(p, sig, sig_len);
	OPENSSL_free(sig);
	EVP_MD_CTX_cleanup(ctx);

	return 1;

err:
	EVP_MD_CTX_cleanup(ctx);

	return 0;
}

int verify_signature(unsigned char *msg, int msg_len, int sig_type, int sig_len, unsigned char *sig, EVP_PKEY *pub)
{
	int rc;
	EVP_MD_CTX *ctx;

	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
	{
		printf("ERROR: EVP_MD_CTX_create error\n");
		return 0;
	}

	// Verify the signature
	switch (sig_type)
	{
		case NID_sha1:
			rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha1(), NULL, pub);
			break;
		case NID_sha224:
			rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha224(), NULL, pub);
			break;
		case NID_sha256:
			rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub);
			break;
		default:
			printf("ERROR: Unknown Signature Type\n");
	}
	if (rc != 1)
	{
		printf("ERROR: EVP_DigestVerifyInit error\n");
		goto err;
	}

	rc = EVP_DigestVerifyUpdate(ctx, msg, msg_len);
	if (rc != 1)
	{
		printf("ERROR: EVP_DigestVerifyUpdate failed\n");
		goto err;
	}

	rc = EVP_DigestVerifyFinal(ctx, sig, sig_len);
	if (rc != 1)
	{
		printf("ERROR: EVP_DigestVerifyFinal failed\n");
		goto err;
	}
	else
	{
		printf("PROGRESS: Verify Success!\n");
	}

	EVP_MD_CTX_cleanup(ctx);
	return 1;
err:
	EVP_MD_CTX_cleanup(ctx);
	return 0;
}
