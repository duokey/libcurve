/*  =========================================================================
    mpc_mpc_curve_codec - core CurveZMQ engine (rfc.zeromq.org/spec:26), adapted
                      to MPC.

    Copyright (c) the Contributors as noted in the AUTHORS file.
    This file is part of the Curve authentication and encryption library.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
    =========================================================================
*/

#include "../src/curve_classes.h" 
#include "mpc_cert.h"

typedef struct _mpc_curve_codec_t mpc_curve_codec_t;
#define MPC_CURVE_CODEC_T_DEFINED

//  @interface
//  Create a new mpc_curve_codec client instance. Caller provides the
//  permanent cert for the client.
mpc_curve_codec_t * mpc_curve_codec_new_client (mpc_cert_t *cert, char *access_token, char* vault_id);

//  Create a new mpc_curve_codec server instance. Caller provides the
//  permanent cert for the server, and optionally a context used
//  for inproc authentication of client keys over ZAP (0MQ RFC 27).
mpc_curve_codec_t * mpc_curve_codec_new_server (mpc_cert_t *cert, char *access_token, char* vault_id, zctx_t *ctx);

//  Destructor
void mpc_curve_codec_destroy (mpc_curve_codec_t **self_p);

//  Set permanent cert for this codec; takes ownership of cert and
//  destroys when destroying the codec.
void mpc_curve_codec_set_permakey (mpc_curve_codec_t *self, mpc_cert_t *cert);

//  Set a metadata property; these are sent to the peer after the
//  security handshake. Property values are strings.
void mpc_curve_codec_set_metadata (mpc_curve_codec_t *self, char *name, char *value);

//  Set tracing on mpc_curve_codec instance. Will report activity to stdout.
void mpc_curve_codec_set_verbose (mpc_curve_codec_t *self, bool verbose);

//  Accept input command from peer. If the command is invalid, it is
//  discarded silently. May return a blob to send to the peer, or NULL
//  if there is nothing to send. Takes ownership of input.
zframe_t * mpc_curve_codec_execute (mpc_curve_codec_t *self, zframe_t **input_p);

//  Encode clear-text message to peer. Returns a blob ready to send
//  on the wire. Encodes frame 'more' property.
zframe_t *
    mpc_curve_codec_encode (mpc_curve_codec_t *self, zframe_t **cleartext_p);

//  Decode blob into message from peer. Takes ownership of encrypted frame.
//  Sets frame 'more' property for application use.
zframe_t * mpc_curve_codec_decode (mpc_curve_codec_t *self, zframe_t **encrypted_p);

//  Indicate whether handshake is still in progress
bool mpc_curve_codec_connected (mpc_curve_codec_t *self);

//  Indicate whether codec hit a fatal error
bool mpc_curve_codec_exception (mpc_curve_codec_t *self);

//  Returns metadata from peer, as a zhash table. The hash table remains
//  owned by the codec and the caller should not use it after destroying
//  the codec. Only valid after the peer has connected. NOTE: All keys
//  in the hash table are lowercase.
zhash_t * mpc_curve_codec_metadata (mpc_curve_codec_t *self);

//  Self test of this class
void mpc_curve_codec_test (bool verbose, char* access_token, char* vault_id);
//  @end


