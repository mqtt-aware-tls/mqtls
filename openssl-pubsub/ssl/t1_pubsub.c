/* ssl/t1_reneg.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2009 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
#include <stdio.h>
#include <openssl/objects.h>
#include <openssl/queue.h>
#include "ssl_locl.h"
#include "logs.h"
#include "ec_func.h"
#include <openssl/pubsub.h>

int ssl_add_clienthello_pubsub_ext(SSL *s, unsigned char *p, int *len,
                                        int maxlen)
{
  fstart("s: %p, p: %p, len: %p, maxlen: %d", s, p, len, maxlen);
 
  EC_GROUP *group;
  BN_CTX *ctx;
  unsigned char *pstr, *init;
  int plen, klen;
  struct keypair *ecdhe;
  struct ps_state_st *ps_state;
  EVP_MD_CTX *md_ctx;
  unsigned char k[SHA256_DIGEST_LENGTH];

  init = p;

  ps_state = s->ps_state = get_ps_state_from_table(s, s->topic, s->tlen);
  if (!s->ps_state)
  {
    psdebug("Make new ps_state with a topic: %s", s->topic);
    ps_state = s->ps_state = init_ps_state();
    ps_state->topic = s->topic;
    ps_state->tlen = s->tlen;
    if (s->role == TLSPS_ROLE_PUBLISHER)
    {
      ps_state->key = generate_payload_encryption_key();
      ps_state->klen = MAX_PAYLOAD_ENC_KEY_LEN;
    }
    else
    {
      ps_state->key = NULL;
      ps_state->klen = 0;
    }
    ps_state->sequence = 0;
    add_ps_state_to_table(s->ctx->table, ps_state);
  }

  // role (1 bytes) || length of a topic (2 bytes) || topic (tlen bytes)
  // || length of a DH public key (2 bytes) || DH pubkey (klen bytes)
  if (p)
  {
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    plen = 2 * 256 / 8 + 1;
    ctx = BN_CTX_new();

    if (s->role == TLSPS_ROLE_SUBSCRIBER)
    {
      psdebug("ClientHello for a subscriber");
    }
    else if (s->role == TLSPS_ROLE_PUBLISHER)
    {
      psdebug("ClientHello for a publisher");
    }
    else
    {
      psdebug("Error: Unknown role");
    }

    // Send a role (a publisher or a subscriber)
    *(p++) = s->role;

    // Send a topic
    s2n(s->tlen, p);
    memcpy(p, s->topic, s->tlen);
    p += s->tlen;
    psdebug("Length of a topic: %d", s->tlen);
    psdebug("Topic: %s", s->topic);

    // Make a ephemeral DH key pair: (a, g^a)
    make_keypair(&ecdhe, group, ctx);
    s->ecdhe = ecdhe;

    *len = 1 + 2 + s->tlen;
    if (s->role == TLSPS_ROLE_SUBSCRIBER)
    {
      // Send a DH public key 
      pub_to_char(ecdhe->pub, &pstr, &plen, group, ctx);
      psdebug("Length of a DH public key: %d", plen);
      s2n(plen, p);
      memcpy(p, pstr, plen);
      p += plen;
      *len += 2 + plen;

      md_ctx = EVP_MD_CTX_create();
      EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
      EVP_DigestUpdate(md_ctx, pstr, plen);
      EVP_DigestFinal_ex(md_ctx, k, &klen);
      s->key = (unsigned char *)malloc(klen);
      memcpy(s->key, k, klen);
      s->klen = klen;
    }
  }
  s->pubsub = 0;

  psprint("Sent ClientHello", init, 0, *len, 10);

  fend();
  return 1;
}

int ssl_parse_clienthello_pubsub_ext(SSL *s, unsigned char *d, int len,
                                          int *al)
{
  fstart("s: %p, d: %p, len: %d, al: %p", s, d, len, al);
  psdebug("TLS-PS required");
  unsigned char *topic, *key, *msg;
  unsigned char k[SHA256_DIGEST_LENGTH];
  int tlen;
  int klen;
  int mlen;
  struct message_queue_st *queue;
  struct message_st *message;
  EVP_MD_CTX *ctx;

  psprint("Received ClientHello", d, 0, len, 10);

  s->pubsub = 1;
  msg = d;
  mlen = len;

  s->peer_role = *(d++);

  if (s->peer_role == TLSPS_ROLE_SUBSCRIBER)
  {
    psdebug("ClientHello for a subscriber");
  }
  else if (s->peer_role == TLSPS_ROLE_PUBLISHER)
  {
    psdebug("ClientHello for a publisher");
  }
  else
  {
    psdebug("Error: Unknown role");
  }

  n2s(d, tlen);
  topic = d;

  s->topic = (unsigned char *)malloc(tlen);
  memcpy(s->topic, topic, tlen);
  s->tlen = tlen;

  d += tlen;

  if (s->peer_role == TLSPS_ROLE_SUBSCRIBER)
  {
    ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    n2s(d, klen);
    key = d;

    psdebug("Length of a DH key: %d", klen);
    EVP_DigestUpdate(ctx, key, klen);
    EVP_DigestFinal_ex(ctx, k, &klen);
    psdebug("Length of a key for a message queue: %d", klen);
    psdebug("Topic (%d bytes): %s", tlen, topic);

    s->key = (unsigned char *)malloc(klen);
    memcpy(s->key, k, klen);
    s->klen = klen;

    queue = get_message_queue(s);
    message = init_message(topic, tlen, k, klen, msg, mlen);
    add_message_to_queue(s, message);
    print_message_queue(s);
  }

  fend();
  return 1;
}

int ssl_add_serverhello_pubsub_ext(SSL *s, unsigned char *p, int *len,
                                        int maxlen)
{
  fstart("s: %p, p: %p, len: %p, maxlen: %d");
  struct message_queue_st *queue;
  struct message_st *msg;
  unsigned char *init;
  int num;

  init = p;
  *len = 0;

  if (p && s->peer_role == TLSPS_ROLE_SUBSCRIBER)
  {
    psdebug("The client is a subscriber");
  }
  else if (p && s->peer_role == TLSPS_ROLE_PUBLISHER)
  {
    // # of messages (2 bytes) || length of m_{Sub1} (2 bytes) || m_{Sub1}
    // || length of m_{Sub2} (2 bytes) || m_{Sub2} || ...
    psdebug("The client is a publisher");
    p += 2;
    *len += 2;
    num = 0;

    queue = get_message_queue(s);
    print_message_queue(s);

    msg = get_message_from_queue(s);
    while (msg)
    {
      num++;
      s2n(msg->mlen, p);
      memcpy(p, msg->msg, msg->mlen);
      p += msg->mlen;
      *len += 2 + msg->mlen;
      msg = get_message_from_queue(s);
    }

    psdebug("Number of messages: %d", num);
    s2n(num, init);
    init -= 2;
  }
  else
  {
    psdebug("Error: Nothing to do");
  }

  psprint("Sent ServerHello", init, 0, *len, 10);
  fend();
  return 1;
}

int ssl_parse_serverhello_pubsub_ext(SSL *s, unsigned char *d, int len,
                                          int *al)
{
  fstart("s: %p, d: %p, len: %d, al: %p", s, d, len, al);
  int i, num, mlen, tlen, klen, slen, xlen, diff;
  unsigned char *topic, *key;
  unsigned char sec[SHA256_DIGEST_LENGTH];
  unsigned char k[SHA256_DIGEST_LENGTH];
  struct ps_state_st *ps_state;
  struct ps_req *ps_req;
  EC_GROUP *group;
  BN_CTX *ctx;
  BIGNUM *x, *y;
  EC_POINT *secret, *peer_pub;
  EVP_MD_CTX *md_ctx;

  psdebug("TLS-PS enabled");
  psprint("Received ServerHello", d, 0, len, 10);
  s->pubsub = 1;
  
  if (s->role == TLSPS_ROLE_PUBLISHER)
  {
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    ctx = BN_CTX_new();

    ps_state = get_ps_state_from_table(s, s->topic, s->tlen);
    psdebug("ps_state: %p", ps_state);

    n2s(d, num);
    psdebug("Number of messages: %d", num);

    while (num > 0)
    {
      x = BN_new();
      y = BN_new();
      secret = EC_POINT_new(group);
      peer_pub = EC_POINT_new(group);

      n2s(d, mlen);
      d++; // role
      n2s(d, tlen);
      if (tlen != s->tlen)
      {
        psdebug("Error: wrong topic length");
      }
      else
      {
        if (strncmp(d, s->topic, tlen))
        {
          psdebug("Error: wrong topic");
        }
      }
      d += tlen;
      n2s(d, klen);
      key = d;
      d += klen;

      char_to_pub(key, klen, peer_pub, group, ctx);
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

        for (i=diff-1; i>=0; i--)
          sec[i] = 0;
      }

      md_ctx = EVP_MD_CTX_create();
      EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);

      psdebug("Length of a DH key: %d", klen);
      EVP_DigestUpdate(md_ctx, key, klen);
      EVP_DigestFinal_ex(md_ctx, k, &klen);

      psprint("Key", k, 0, klen, 10);
      ps_req = init_ps_req(k, klen, sec, slen);
      add_ps_req_to_ps_state(ps_state, ps_req);
      num--;
      psdebug("Number of messages left: %d", num);
      BN_free(x);
      BN_free(y);
      EC_POINT_free(secret);
      EC_POINT_free(peer_pub);
    }

    EC_GROUP_free(group);
    BN_CTX_free(ctx);
  }

  fend();
  return 1;
}
