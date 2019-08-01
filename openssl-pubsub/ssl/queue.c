#include <openssl/ssl.h>
#include <openssl/queue.h>
#include "logs.h"

int init_message_queue(SSL_CTX *ctx)
{
  fstart("ctx: %p", ctx);
  struct message_queue_st *queue;
  if (!ctx) goto err;
  queue = ctx->queue = (struct message_queue_st *)malloc(sizeof(struct message_queue_st));
  memset(queue, 0x0, sizeof(struct message_queue_st));
  fend();
  return SUCCESS;
err:
  ferr();
  return FAILURE;
}

void free_message_queue(SSL_CTX *ctx)
{
  fstart("ctx: %p", ctx);
  struct message_st *curr, *next;

  if (ctx)
  {
    if (ctx->queue)
    {
      if (ctx->queue->num > 0)
      {
        curr = ctx->queue->head;
        next = curr->next;
        while (curr)
        {
          free_message(curr);
          curr = next;
          if (curr)
            next = curr->next;
        }
      }
      free(ctx->queue);
    }
  }
  fend();
}

struct message_queue_st *get_message_queue(SSL *s)
{
  fstart("s: %p", s);
  fend("queue: %p", s->ctx->queue);
  return s->ctx->queue;
}

void print_message_queue(SSL *s)
{
  fstart("s: %p", s);
  int idx;
  struct message_queue_st *queue;
  struct message_st *msg;
  queue = get_message_queue(s);
  msg = queue->head;

  psdebug("Number of Messages: %d\n", queue->num);
  idx = 0;
  while (msg)
  {
    psdebug("========== (index: %d) ==========", idx++);
    psdebug("Topic (%d bytes): %s", msg->tlen, msg->topic);
    psprint("Key", msg->key, 0, msg->klen, 10);
    psprint("Message", msg->msg, 0, msg->mlen, 10);
    psdebug("=================================\n");
    msg = msg->next;
  }
  fend();
}

struct message_st *init_message(unsigned char *topic, int tlen, 
    unsigned char *key, int klen,
    unsigned char *msg, int mlen)
{
  fstart("topic: %p, tlen: %d, key: %p, klen: %d, msg: %p, mlen: %d",
      topic, tlen, key, klen, msg, mlen);
  struct message_st *ret;
  ret = (struct message_st *)malloc(sizeof(struct message_st));

  ret->topic = (unsigned char *)malloc(tlen);
  if (!(ret->topic)) goto err;
  memcpy(ret->topic, topic, tlen);
  ret->tlen = tlen;

  ret->key = (unsigned char *)malloc(klen);
  if (!(ret->key)) goto err;
  memcpy(ret->key, key, klen);
  ret->klen = klen;

  ret->msg = (unsigned char *)malloc(mlen);
  if (!(ret->msg)) goto err;
  memcpy(ret->msg, msg, mlen);
  ret->mlen = mlen;

  ret->prev = NULL;
  ret->next = NULL;
  fend("ret: %p", ret);
  return ret;
err:
  ferr();
  return NULL;
}

void free_message(struct message_st *msg)
{
  fstart("msg: %p", msg);
  if (msg)
  {
    if (msg->key)
      free(msg->key);
    msg->klen = 0;
    if (msg->msg)
      free(msg->msg);
    msg->mlen = 0;
  }
  fend();
}

void add_message_to_queue(SSL *s, struct message_st *msg)
{
  fstart("s: %p, msg: %p", s, msg);
  struct message_queue_st *queue;
  queue = s->ctx->queue;
  if (!(queue->head))
    queue->head = msg;

  if (queue->tail)
  {
    msg->prev = queue->tail;
    queue->tail->next = msg;
  }
  queue->tail = msg;
  queue->num++;
  fend();
}

struct message_st *get_message_from_queue(SSL *s)
{
  fstart("s: %p", s);
  struct message_queue_st *queue;
  struct message_st *msg, *ret;
  unsigned char *topic;
  int tlen;
  ret = NULL;

  topic = s->topic;
  tlen = s->tlen;

  psdebug("Topic (%d bytes): %s", tlen, topic);

  queue = get_message_queue(s);
  msg = queue->head;
  while (msg)
  {
    if (msg->tlen == tlen)
    {
      if (!strncmp(msg->topic, topic, tlen))
      {
        psdebug("Found the message related to the topic: %p", msg);
        ret = msg;
        if (ret->prev)
        {
          ret->prev->next = ret->next;
          if (ret->next) // if ret is not the last one
          {
            ret->next->prev = ret->prev;
          }
        }
        else // if ret is the first one
        {
          queue->head = ret->next;
        }
        queue->num--;
        if (queue->num == 0)
        {
          queue->head = NULL;
          queue->tail = NULL;
        }
        break;
      }
    }
    msg = msg->next;
  }

  fend("ret: %p", ret);
  return ret;
}

struct message_st *get_key_material_from_queue(SSL *s)
{
  fstart("s: %p", s);
  struct message_queue_st *queue;
  struct message_st *msg, *ret;
  unsigned char *key;
  int klen;
  ret = NULL;

  key = s->key;
  klen = s->klen;

  psprint("Key", key, 0, klen, 10);

  queue = get_message_queue(s);
  msg = queue->head;
  while (msg)
  {
    if (msg->klen == klen)
    {
      if (!strncmp(msg->key, key, klen))
      {
        psdebug("Found the message related to the key: %p", msg);
        ret = msg;
        if (ret->prev)
        {
          ret->prev->next = ret->next;
          if (ret->next) // if ret is not the last one
          {
            ret->next->prev = ret->prev;
          }
        }
        else // if ret is the first one
        {
          queue->head = ret->next;
        }
        queue->num--;
        if (queue->num == 0)
        {
          queue->head = NULL;
          queue->tail = NULL;
        }
        break;
      }
    }
    msg = msg->next;
  }

  fend("ret: %p", ret);
  return ret;
}
