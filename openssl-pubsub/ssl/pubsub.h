#ifndef __PUBSUB_H__
#define __PUBSUB_H__

#include <openssl/ssl.h>
#include <openssl/queue.h>
#include <openssl/evp.h>
#define STATE_FILE "state"
#define MAX_PAYLOAD_ENC_KEY_LEN 32

#define TLSPS_POS_PUB_WRITE     0
#define TLSPS_POS_BROKER_WRITE  1
#define TLSPS_POS_SUB_READ      2
#define TLSPS_POS_BROKER_READ   3

struct keypair
{
  BIGNUM *pri;
  EC_POINT *pub;
};

struct ps_req_st {
  unsigned char *key; // H(g^a)
  int klen;
  unsigned char *secret;
  int slen;
  struct ps_req_st *next;
};

struct ps_state_st {
  int state;
  unsigned char *topic;
  int tlen;
  unsigned char *key; // payload encryption key
  int klen;
  int sequence;
  int rnum;
  struct ps_req_st *head;
  struct ps_state_st *next;
};

struct ps_state_table_st {
  int num;
  struct ps_state_st *head;
  struct ps_state_st *tail;
};

struct ps_state_table_st *init_ps_state_table(void);
void load_ps_state_from_file(struct ps_state_table_st *table, const char *fname);
void store_ps_state_to_file(struct ps_state_table_st *table, const char *fname);
void free_ps_state_table(SSL_CTX *ctx);
void print_ps_state_table(SSL *s);

struct ps_state_st *init_ps_state(void);
void free_ps_state(struct ps_state_st *state);
int add_ps_state_to_table(struct ps_state_table_st *table, struct ps_state_st *state);
struct ps_state_st *get_ps_state_from_table(SSL *s, unsigned char *topic, int tlen);
unsigned char *generate_payload_encryption_key();

struct ps_req_st *init_ps_req(unsigned char *key, int klen,
    unsigned char *secret, int slen);
void free_ps_req(struct ps_req_st *req);
int add_ps_req_to_ps_state(struct ps_state_st *state, struct ps_req_st *req);
struct ps_req_st *get_ps_req_from_ps_state(struct ps_state_st *state);

int set_topic(SSL *ssl, unsigned char *topic, int tlen);
int set_key(SSL *ssl, unsigned char *key, int klen);

int get_topic(SSL *ssl, unsigned char *topic, int *tlen);
int get_key(SSL *ssl, unsigned char *key, int *klen);
int get_sequence(SSL *ssl);

int need_handshake(SSL *ssl);
int do_write_process_pubsub(SSL *ssl, void *buf, int *len);
int do_read_process_pubsub(SSL *ssl, void *buf, int *len);

int check_publish_message(void *buf, int len, int pos);

int get_payload_encryption_key(SSL *s, void *buf, int *len);
int send_payload_encryption_keys(SSL *s, void *buf, int *len,
    struct ps_state_st *ps_state);
int forward_payload_encryption_key(SSL *s, void *buf, int *len,
    struct message_st *msg);
int store_payload_encryption_keys(SSL *s, void *buf, int *len);

int encrypt_payload(SSL *s, void *buf, int *len);
int decrypt_payload(SSL *s, void *buf, int *len);

int make_signature_block(unsigned char **sigblk, unsigned char *msg, int mlen, 
    EVP_PKEY *priv, int nid, int *slen);
int verify_signature(unsigned char *msg, int msg_len, int sig_type, 
    int sig_len, unsigned char *sig, EVP_PKEY *pub);
#endif /* __PUBSUB_H__ */
