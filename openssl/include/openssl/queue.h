#ifndef __QUEUE_H__
#define __QUEUE_H__

struct message_st {
  unsigned char *topic;
  int tlen;
  unsigned char *key;
  int klen;
  unsigned char *msg;
  int mlen;
  struct message_st *prev;
  struct message_st *next;
};

struct message_queue_st {
  int num;
  struct message_st *head;
  struct message_st *tail;
};

int init_message_queue(SSL_CTX *ctx);
void free_message_queue(SSL_CTX *ctx);
struct message_queue_st *get_message_queue(SSL *ssl);
void print_message_queue(SSL *ssl);

struct message_st *init_message(unsigned char *topic, int tlen, 
    unsigned char *key, int klen,
    unsigned char *msg, int mlen);
void free_message(struct message_st *msg);

void add_message_to_queue(SSL *s, struct message_st *msg);
struct message_st *get_message_from_queue(SSL *s);
struct message_st *get_key_material_from_queue(SSL *s);

#endif /* __QUEUE_H__ */
