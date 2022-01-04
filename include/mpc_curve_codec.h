/*  =========================================================================
    mpc_curve_codec - core CurveZMQ engine (rfc.zeromq.org/spec:26), adapted
                      to MPC.

    Copyright (c) the Contributors as noted in the AUTHORS file.
    This file is part of the Curve authentication and encryption library.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
    =========================================================================
*/

#include "../src/curve_classes.h" 

typedef struct _curve_codec_t curve_codec_t;
#define MPC_CURVE_CODEC_T_DEFINED

//  @interface
//  Create a new curve_codec client instance. Caller provides the
//  permanent cert for the client.
curve_codec_t * curve_codec_new_client (zcert_t *cert);

//  Create a new curve_codec server instance. Caller provides the
//  permanent cert for the server, and optionally a context used
//  for inproc authentication of client keys over ZAP (0MQ RFC 27).
curve_codec_t * curve_codec_new_server (zcert_t *cert, zctx_t *ctx);

//  Destructor
void curve_codec_destroy (curve_codec_t **self_p);

//  Set permanent cert for this codec; takes ownership of cert and
//  destroys when destroying the codec.
void curve_codec_set_permakey (curve_codec_t *self, zcert_t *cert);

//  Set a metadata property; these are sent to the peer after the
//  security handshake. Property values are strings.
void curve_codec_set_metadata (curve_codec_t *self, char *name, char *value);

//  Set tracing on curve_codec instance. Will report activity to stdout.
void curve_codec_set_verbose (curve_codec_t *self, bool verbose);

//  Accept input command from peer. If the command is invalid, it is
//  discarded silently. May return a blob to send to the peer, or NULL
//  if there is nothing to send. Takes ownership of input.
zframe_t * curve_codec_execute (curve_codec_t *self, zframe_t **input_p);

//  Encode clear-text message to peer. Returns a blob ready to send
//  on the wire. Encodes frame 'more' property.
zframe_t *
    curve_codec_encode (curve_codec_t *self, zframe_t **cleartext_p);

//  Decode blob into message from peer. Takes ownership of encrypted frame.
//  Sets frame 'more' property for application use.
zframe_t * curve_codec_decode (curve_codec_t *self, zframe_t **encrypted_p);

//  Indicate whether handshake is still in progress
bool curve_codec_connected (curve_codec_t *self);

//  Indicate whether codec hit a fatal error
bool curve_codec_exception (curve_codec_t *self);

//  Returns metadata from peer, as a zhash table. The hash table remains
//  owned by the codec and the caller should not use it after destroying
//  the codec. Only valid after the peer has connected. NOTE: All keys
//  in the hash table are lowercase.
zhash_t * curve_codec_metadata (curve_codec_t *self);

//  Self test of this class
void mpc_curve_codec_test (bool verbose, char* access_token, char* vault_id);
//  @end


