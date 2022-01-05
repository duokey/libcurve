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

/*
@header
    Implements the client and server codecs. This class encodes and decodes
    zframes. All I/O is the responsibility of the caller. This is the
    reference implementation of CurveZMQ. You will not normally want to use
    it directly in application code as the API is low-level and complex.
@discuss
@end
*/

#include "../../include/mpc_curve_library.h"
#include "sodium.h"
#if crypto_box_PUBLICKEYBYTES != 32 \
 || crypto_box_SECRETKEYBYTES != 32 \
 || crypto_box_BEFORENMBYTES != 32 \
 || crypto_box_ZEROBYTES != 32 \
 || crypto_box_BOXZEROBYTES != 16 \
 || crypto_box_NONCEBYTES != 24
#   error "libsodium not built correctly"
#endif

typedef enum {
    send_hello,                 //  C: sends HELLO to server
    expect_hello,               //  S: accepts HELLO from client
    expect_welcome,             //  C: accepts WELCOME from server
    expect_initiate,            //  S: accepts INITIATE from client
    expect_ready,               //  C: accepts READY from server
    expect_message,             //  C/S: accepts MESSAGE from server
    exception                     //  Error condition, no work possible
} state_t;

//  For parsing incoming commands

typedef enum {
    no_command,
    hello_command,
    welcome_command,
    initiate_command,
    ready_command,
    message_command
} command_t;

//  To make calls to DuoKey-KMS
/*
struct _mpc_params_t {
   char * access_token;
   char * vault_id;            
};*/

//  Structure of our class
struct _mpc_curve_codec_t {
    zctx_t *ctx;                //  Context for ZAP authentication
    mpc_cert_t *permacert;      //  Our permanent certificate (i.e., long-term keys are MPC keys)
    zcert_t *transcert;         //  Our transient certificate

    bool verbose;               //  Trace activity to stdout
    state_t state;              //  Current codec state
    int64_t nonce_counter;      //  Counter for short nonces
    zhash_t *metadata_sent;     //  Metadata sent to peer
    zhash_t *metadata_recd;     //  Metadata received from peer
    byte *metadata_data;        //  Serialized metadata
    size_t metadata_size;       //  Size of serialized metadata
    size_t metadata_curr;       //  Size during serialization process
    bool is_server;             //  True for server-side codec
    char error_text [128];      //  In case of an error

    //  At some point we have to know the public keys for our peer
    byte peer_permakey [32];    //  Permanent public key for peer
    byte peer_transkey [32];    //  Transient public key for peer
    byte precomputed [32];      //  Precomputed transient key

    //  Server connection properties
    byte cookie_key [32];       //  Server cookie key

    //  Client connection properties
    byte cookie [96];           //  Cookie from server
};

//  Command structures

typedef struct {
    char id [sizeof ("HELLO")];
    byte version [2];           //  CurveZMQ major-minor version
    byte padding [72];          //  Anti-amplification padding
    byte client [32];           //  Client public short-term connection key C'
    byte nonce [8];             //  Short nonce, prefixed by "CurveZMQHELLO---"
    byte box [80];              //  Signature, Box [64 * %x0](C'->S)
} hello_t;

typedef struct {
    char id [sizeof ("WELCOME")];
    byte nonce [16];            //  Long nonce, prefixed by "WELCOME-"
    byte box [144];             //  Box [S' + cookie](S->C')
} welcome_t;

typedef struct {
    char id [sizeof ("INITIATE")];
    byte cookie [96];           //  Server-provided cookie
    byte nonce [8];             //  Short nonce, prefixed by "CurveZMQINITIATE"
    byte box [144];             //  Box [C + vouch + metadata](C'->S')
} initiate_t;

typedef struct {
    char id [sizeof ("READY")];
    byte nonce [8];             //  Short nonce, prefixed by "CurveZMQREADY---"
    byte box [16];              //  Box [metadata](S'->C')
} ready_t;

typedef struct {
    char id [sizeof ("MESSAGE")];
    byte nonce [8];             //  Short nonce, prefixed by "CurveZMQMESSAGE-"
    byte box [16];              //  Box [payload](S'->C') or (C'->S')
} message_t;

//  --------------------------------------------------------------------------
//  Constructors
//  Create a new mpc_curve_codec client instance. Caller provides the
//  permanent certificate for the client.

mpc_curve_codec_t *
mpc_curve_codec_new_client (mpc_cert_t *cert)
{
    mpc_curve_codec_t *self = (mpc_curve_codec_t *) zmalloc (sizeof (mpc_curve_codec_t));
    assert (self);
    assert (cert);

    self->is_server = false;
    self->state = send_hello;

    self->metadata_sent = zhash_new ();
    zhash_autofree (self->metadata_sent);
    self->metadata_recd = zhash_new ();
    zhash_autofree (self->metadata_recd);
    self->permacert = mpc_cert_dup (cert);      // Client's long-term key is MPC
    self->transcert = zcert_new ();             // Client's short-term key is not MPC
    //self->transcert = zcert_load ("../certs/short-term/client.cert");
    puts("\n******Client short-term*******\n");
    zcert_print(self->transcert);

    return self;
}


//  --------------------------------------------------------------------------
//  Create a new mpc_curve_codec server instance. Caller provides the
//  permanent cert for the server, and optionally a context used
//  for inproc authentication of client keys over ZAP (0MQ RFC 27).

mpc_curve_codec_t *
mpc_curve_codec_new_server (mpc_cert_t *cert, zctx_t *ctx)
{
    mpc_curve_codec_t *self = (mpc_curve_codec_t *) zmalloc (sizeof (mpc_curve_codec_t));
    assert (self);
    assert (cert);

    self->ctx = ctx;
    self->is_server = true;
    self->state = expect_hello;

    self->metadata_sent = zhash_new ();
    zhash_autofree (self->metadata_sent);
    self->metadata_recd = zhash_new ();
    zhash_autofree (self->metadata_recd);
    self->permacert = mpc_cert_dup (cert);      // Server's long-term key is MPC
    //  We don't generate a transient cert yet because that uses up
    //  entropy so would allow arbitrary clients to do a DoS attack.

    return self;
}


//  --------------------------------------------------------------------------
//  Destructor

void
mpc_curve_codec_destroy (mpc_curve_codec_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        mpc_curve_codec_t *self = *self_p;
        mpc_cert_destroy (&self->permacert);
        zcert_destroy (&self->transcert);
        zhash_destroy (&self->metadata_sent);
        zhash_destroy (&self->metadata_recd);
        free (self->metadata_data);
        free (self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Set a metadata property; these are sent to the peer after the security
//  handshake. Property values are strings.

void
mpc_curve_codec_set_metadata (mpc_curve_codec_t *self, char *name, char *value)
{
    assert (self);
    assert (name && value);
    assert (strlen (name) > 0 && strlen (name) < 256);
    zhash_insert (self->metadata_sent, name, value);
}


//  --------------------------------------------------------------------------
//  Set tracing on mpc_curve_codec instance. Will report activity to stdout.

void
mpc_curve_codec_set_verbose (mpc_curve_codec_t *self, bool verbose)
{
    assert (self);
    self->verbose = verbose;
}


//  --------------------------------------------------------------------------
//  Internal functions for working with CurveZMQ commands

static void
s_raise_exception (mpc_curve_codec_t *self, char *error_text)
{
    strcpy (self->error_text, error_text);
    self->state = exception;
}

//  Encrypt a block of data using the connection nonce. If
//  key_to/key_from are null, uses precomputed key.

static int
s_encrypt (
    mpc_curve_codec_t *self,    //  Codec instance sending the data
    byte *target,           //  target must be nonce + box
    byte *data,             //  Clear text data to encrypt
    size_t size,            //  Size of clear text data
    char *prefix,           //  Nonce prefix to use, 8 or 16 chars
    byte *key_to,           //  Public key to encrypt to, may be null
    byte *key_from,         //  Secret key to encrypt from, may be null
    char *key_id_from)      //  Secret key id to encrypt from, may be null
{
    //  Plain and encoded buffers are the same size; plain buffer starts
    //  with 32 (ZEROBYTES) zeros and box starts with 16 (BOXZEROBYTES)
    //  zeros. box_size is combined size, the same in both cases, and
    //  encrypted data is thus 16 bytes longer than plain data.
    size_t box_size = crypto_box_ZEROBYTES + size;
    byte *plain = (byte *) malloc (box_size);
    byte *box = (byte *) malloc (box_size);

    //  Prepare plain text with zero bytes at start for encryption
    memset (plain, 0, crypto_box_ZEROBYTES);
    memcpy (plain + crypto_box_ZEROBYTES, data, size);

    //  Prepare full nonce and store nonce into target
    //  Handle both short and long nonces
    byte nonce [24];
    if (strlen (prefix) == 16) {
        //  Long nonce is sequential integer
        memcpy (nonce, (byte *) prefix, 16);
        memcpy (nonce + 16, &self->nonce_counter, 8);
        memcpy (target, &self->nonce_counter, 8);
        self->nonce_counter++;
        target += 8;            //  Encrypted data comes after 8 byte nonce
    }
    else {
        //  Short nonce is random sequence
        randombytes (target, 16);
        memcpy (nonce, (byte *) prefix, 8);
        memcpy (nonce + 8, target, 16);
        target += 16;           //  Encrypted data comes after 16 byte nonce
    }
    //  Create box using either key-pair (with/without MPC), or precomputed key
    int rc;
    if (key_id_from){
        /**  If secret key id is present, run the ECDH key exchange in MPC **/

        char * key_to_z85 = malloc (sizeof(char)*41);
        zmq_z85_encode (key_to_z85, key_to, 32);

        // Derive symmetric key through X25519 protocol in MPC
        byte * session_key_b64 = kms_x25519(ACCESS_TOKEN, VAULT_ID, key_id_from, key_to_z85);
        char *session_key = b64_decode(session_key_b64, strlen(session_key_b64));

        // Return HSalsa encryption key k. HSalsa20 is an intermediate step towards XSalsa20.
        // It is a helpful tool in the XSalsa20 security proof.
        unsigned char k[32];
        static const unsigned char zero[16] = { 0 };
        rc = crypto_core_hsalsa20(k, zero, session_key, NULL);

        // Encrypt the box with key k (Authenticated Encryption)
        rc = crypto_box_afternm (box, plain, box_size, nonce, k);
    }else if (key_to)
        /**  Otherwise, run the ECDH key exchange without MPC **/
        // Crypto box both derive the symmetric encryption key and encrypt the box with it
        rc = crypto_box (box, plain, box_size, nonce, key_to, key_from);

    else
        /**  If precomputed encryption key is present, directly encrypt the box,
         *   without having to first derive the key.  **/
        rc = crypto_box_afternm (box, plain, box_size, nonce, self->precomputed);

    //  Now copy encrypted data into target; it will be 16 bytes longer than
    //  plain data
    memcpy (target, box + crypto_box_BOXZEROBYTES, size + 16);
    free (plain);
    free (box);
    
    return rc;
}


//  Decrypt a block of data using the connection nonce and precomputed key
//  If key_to/key_from are null, uses precomputed key. Returns 0 if OK,
//  -1 if there was an exception.

static int
s_decrypt (
    mpc_curve_codec_t *self,    //  mpc_curve_codec instance sending the data
    byte *source,           //  Source must be nonce + box
    byte *target,           //  Where to store decrypted clear text
    size_t size,            //  Size of clear text data
    char *prefix,           //  Nonce prefix to use, 8 or 16 chars
    byte *key_to,           //  Key to decrypt to, may be null
    byte *key_from,         //  Key to decrypt from, may be null
    char *key_id_from)      //  Secret key id to decrypt from, may be null
{
    size_t box_size = crypto_box_ZEROBYTES + size;
    byte *plain = (byte *) malloc (box_size);
    byte *box = (byte *) malloc (box_size);

    //  Prepare the full nonce from prefix and source
    //  Handle both short and long nonces
    byte nonce [24];
    if (strlen (prefix) == 16) {
        memcpy (nonce, (byte *) prefix, 16);
        memcpy (nonce + 16, source, 8);
        source += 8;
    }
    else {
        memcpy (nonce, (byte *) prefix, 8);
        memcpy (nonce + 8, source, 16);
        source += 16;
    }
    //  Get encrypted box from source
    memset (box, 0, crypto_box_BOXZEROBYTES);
    memcpy (box + crypto_box_BOXZEROBYTES, source, size + crypto_box_BOXZEROBYTES);

    //  Open box using either key-pair (with/without MPC), or precomputed key
    int rc;
    if (key_id_from){
        /**  If secret key id is present, run the ECDH key exchange in MPC **/

        char * key_to_z85 = malloc (sizeof(char)*41);
        zmq_z85_encode (key_to_z85, key_to, 32);

        // Derive symmetric key through X25519 protocol in MPC
        byte *session_key_b64 = kms_x25519(ACCESS_TOKEN, VAULT_ID, key_id_from, key_to_z85);
        char *session_key = b64_decode(session_key_b64, strlen(session_key_b64));
        print_in_bytes(session_key, 32);

        // Return HSalsa encryption key k. HSalsa20 is an intermediate step towards XSalsa20.
        // It is a helpful tool in the XSalsa20 security proof.
        unsigned char k[32];
        static const unsigned char zero[16] = { 0 };
        rc = crypto_core_hsalsa20(k, zero, session_key, NULL);

        // Decrypt the box with key k (Authenticated Encryption)
        rc = crypto_box_open_afternm (plain, box, box_size, nonce, k);
    }else if (key_to)
        /**  Otherwise, run the ECDH key exchange without MPC **/
        // Crypto box both derive the symmetric encryption key and decrypt the box with it
        rc = crypto_box_open (plain, box, box_size, nonce, key_to, key_from);
    else
        /**  If precomputed encryption key is present, directly decrypt the box,
         *   without having to first derive the key.  **/
        rc = crypto_box_open_afternm (plain, box, box_size, nonce, self->precomputed);

    //  If we cannot open the box (i.e., incorrect MAC), it means it's been modified or is unauthentic
    if (rc == 0)
        memcpy (target, plain + crypto_box_ZEROBYTES, size);
    else
    if (self->verbose)
        puts ("E: invalid box received, cannot open it");

    free (plain);
    free (box);
    return rc;
}

static int
s_count_total_size (const char *name, void *value, void *arg)
{
    mpc_curve_codec_t *self = (mpc_curve_codec_t *) arg;
    self->metadata_size += strlen (name) + strlen ((char *) value) + 5;
    return 0;
}

static int
s_encode_property (const char *name, void *value, void *arg)
{
    mpc_curve_codec_t *self = (mpc_curve_codec_t *) arg;
    byte *needle = self->metadata_data + self->metadata_curr;
    size_t name_len = strlen (name);
    size_t value_len = strlen ((char *) value);

    //  Encode name
    *needle++ = (byte) name_len;
    memcpy (needle, (byte *) name, name_len);
    needle += name_len;

    //  Encode value
    *needle++ = (byte) ((value_len >> 24) & 255);
    *needle++ = (byte) ((value_len >> 16) & 255);
    *needle++ = (byte) ((value_len >> 8)  & 255);
    *needle++ = (byte) ((value_len)       & 255);
    memcpy (needle, (byte *) value, value_len);
    needle += value_len;

    self->metadata_curr = needle - self->metadata_data;
    return 0;
}


//  Encode self->metadata_sent into buffer ready to send

static void
s_encode_metadata (mpc_curve_codec_t *self)
{
    self->metadata_size = 0;
    zhash_foreach (self->metadata_sent, s_count_total_size, self);
    self->metadata_data = (byte *) malloc (self->metadata_size);
    self->metadata_curr = 0;
    zhash_foreach (self->metadata_sent, s_encode_property, self);
    assert (self->metadata_curr == self->metadata_size);
}


//  Decode metadata from provided buffer into self->metadata_recd

static void
s_decode_metadata (mpc_curve_codec_t *self, byte *data, size_t size)
{
    byte *needle = data;
    byte *limit = data + size;

    //  Each property uses at least six bytes
    while (needle < limit - 6) {
        size_t name_len;
        size_t value_len;
        name_len = *needle++;
        if (needle + name_len > limit - 5)
            break;      //  Invalid property, skip the rest

        char *name = (char *) malloc (name_len + 1);
        memcpy ((byte *) name, needle, name_len);
        name [name_len] = 0;
        needle += name_len;
        //  Normalize name as all lower-case
        char *char_ptr = name;
        while (*char_ptr) {
            *char_ptr = tolower (*char_ptr);
            char_ptr++;
        }

        value_len = (needle [0] << 24)
                  + (needle [1] << 16)
                  + (needle [2] << 8)
                  +  needle [3];
        needle += 4;
        char *value = (char *) malloc (value_len + 1);
        memcpy ((byte *) value, needle, value_len);
        value [value_len] = 0;
        needle += value_len;

        zhash_insert (self->metadata_recd, name, (char *) value);
        free (name);
        free (value);
    }
}

//  If ZAP context is known, authenticate via ZAP handler; return 0
//  if OK, -1 if not allowed. If no authentication is installed,
//  returns 0.

static int
s_authenticate_peer (mpc_curve_codec_t *self)
{
    if (!self->ctx)
        return 0;

    //  Create a socket for the ZAP request; we'll destroy this as soon
    //  as the request is done, to avoid old sockets accumulating in the
    //  parent context. To check if there is a ZAP handler installed, we
    //  try to bind to the ZAP endpoint and only continue if that failed.
    void *requestor = zsocket_new (self->ctx, ZMQ_REQ);
    if (zsocket_bind (requestor, "inproc://zeromq.zap.01") == 0) {
        zsocket_destroy (self->ctx, requestor);
        return 0;                       //  ZAP not installed
    }
    zsocket_connect (requestor, "inproc://zeromq.zap.01");
    zmsg_t *request = zmsg_new ();
    zmsg_addstr (request, "1.0");       //  ZAP version 1.0
    zmsg_addstr (request, "");          //  Sequence number, unused
    zmsg_addstr (request, "libcurve");  //  Domain, unused
    zmsg_addstr (request, "");          //  Address, unused
    zmsg_addstr (request, "");          //  Identity, unused
    zmsg_addstr (request, "CURVE");     //  Mechanism = CURVE
    zmsg_addmem (request, self->peer_permakey, 32);

    int rc = -1;                        //  By default, denied
    if (zmsg_send (&request, requestor) == 0) {
        zmsg_t *reply = zmsg_recv (requestor);
        if (reply) {
            //  Discard version and sequence number
            free (zmsg_popstr (reply));
            free (zmsg_popstr (reply));
            char *status_code = zmsg_popstr (reply);
            if (streq (status_code, "200"))
                rc = 0;                 //  Authorized OK
            free (status_code);
            zmsg_destroy (&reply);
        }
    }
    zsocket_destroy (self->ctx, requestor);
    return rc;
}


static zframe_t *
s_produce_hello (mpc_curve_codec_t *self)
{
    zframe_t *command = zframe_new (NULL, sizeof (hello_t));
    hello_t *hello = (hello_t *) zframe_data (command);
    memcpy (hello->id, "\x05HELLO", 6);

    memcpy (hello->client, zcert_public_key (self->transcert), 32);
    byte signature [64];
    memset (signature, 0, 64);

    s_encrypt (self, hello->nonce,
               signature, 64,
               "CurveZMQHELLO---",
               self->peer_permakey,                          //  Server long-term public key
               (byte *)zcert_secret_key (self->transcert),   //  Client short-term secret key
               NULL);

    puts("Hello sent");           
    return command;
}

//  Returns 0 if OK, -1 if command or keys were invalid
static int
s_process_hello (mpc_curve_codec_t *self, zframe_t *input)
{
    puts("Process hello");
    hello_t *hello = (hello_t *) zframe_data (input);
    memcpy (self->peer_transkey, hello->client, 32);          // Server receives the client's short-term public key

    

    byte signature_received [64];
    int rc = s_decrypt (self,
        hello->nonce,
        signature_received, 64,
        "CurveZMQHELLO---",
        hello->client,                                       //  Client short-term public key
        NULL,
        mpc_cert_secret_key_id (self->permacert));           //  Server long-term secret key id

    puts("Hello received"); 
    return rc;
}

static zframe_t *
s_produce_welcome (mpc_curve_codec_t *self)
{
    zframe_t *command = zframe_new (NULL, sizeof (welcome_t));
    welcome_t *welcome = (welcome_t *) zframe_data (command);
    memcpy (welcome->id, "\x07WELCOME", 8);

    //  Working variables for libsodium calls
    byte nonce [24];            //  Full nonces are always 24 bytes
    byte plain [128];           //  Space for baking our cookies

    //  Generate client transient key as late as possible. We have not
    //  yet authenticated the client, so it may be hostile, but at least
    //  it knows the server's public key.
    //self->transcert = zcert_load ("../certs/short-term/server.cert");  //zcert_new ();                     // Server's short-term key is not MPC
    self->transcert = zcert_new ();                     // Server's short-term key is not MPC

    //  Generate cookie = Box [C' + s'](t),
    memset (plain, 0, crypto_box_ZEROBYTES);
    memcpy (plain + crypto_box_ZEROBYTES, self->peer_transkey, 32);
    memcpy (plain + crypto_box_ZEROBYTES + 32,
            zcert_secret_key (self->transcert), 32);

    //  Create full nonce for encryption
    //  8-byte prefix plus 16-byte random nonce
    assert (crypto_box_BOXZEROBYTES == 16);
    byte cookie_nonce [16];
    randombytes (cookie_nonce, 16);
    memcpy (nonce, (byte *) "COOKIE--", 8);
    memcpy (nonce + 8, cookie_nonce, 16);

    //  Encrypt using one-time symmetric cookie key
    randombytes (self->cookie_key, 32);
    byte cookie_box [96];
    int rc = crypto_secretbox (cookie_box, plain, 96, nonce, self->cookie_key);
    assert (rc == 0);

    //  Create Box [S' + cookie](S->C')
    memcpy (plain, zcert_public_key (self->transcert), 32);
    memcpy (plain + 32, cookie_nonce, 16);
    memcpy (plain + 48, cookie_box + crypto_box_BOXZEROBYTES, 80);
    s_encrypt (self, welcome->nonce,
               plain, 128,
               "WELCOME-",                                  //  Client short-term public key
               self->peer_transkey,
               NULL,
               mpc_cert_secret_key_id (self->permacert));      //  Server long-term secret key id            

    puts("Welcome sent"); 
    return command;
}

//  Returns 0 if OK, -1 if command or keys were invalid
static int
s_process_welcome (mpc_curve_codec_t *self, zframe_t *input)
{
    //  Open Box [S' + cookie](C'->S)
    byte plain [128];
    welcome_t *welcome = (welcome_t *) zframe_data (input);
    int rc = s_decrypt (self,
        welcome->nonce,
        plain, 128,
        "WELCOME-",
        self->peer_permakey,                            //  Server long-term public key
        (byte *)zcert_secret_key (self->transcert),     //  Client short-term secret key
        NULL);

    if (rc == 0) {
        memcpy (self->peer_transkey, plain, 32);
        memcpy (self->cookie, plain + 32, 96);
    }
    puts("Welcome received");
    return rc;
}

//  Pre-compute connection secret from peer's transient key

static void
s_precompute_key (mpc_curve_codec_t *self)
{
    int rc = crypto_box_beforenm (self->precomputed,
                                  self->peer_transkey,
                                  zcert_secret_key (self->transcert));
    assert (rc == 0);
}

static zframe_t *
s_produce_initiate (mpc_curve_codec_t *self)
{
    //  Create serialized metdata data buffer ready to send
    s_encode_metadata (self);
    zframe_t *command = zframe_new (NULL, sizeof (initiate_t) + self->metadata_size);
    initiate_t *initiate = (initiate_t *) zframe_data (command);
    memcpy (initiate->id, "\x08INITIATE", 9);
    memcpy (initiate->cookie, self->cookie, sizeof (initiate->cookie));

    //  Create vouch = Box [C',S](C->S')
    byte vouch_plain [64];           //  Space for plain text vouch
    byte vouch_crypt [96];
    memcpy (vouch_plain, zcert_public_key (self->transcert), 32);
    memcpy (vouch_plain + 32, self->peer_permakey, 32);
    s_encrypt (self, vouch_crypt,
               vouch_plain, 64,
               "VOUCH---",
               self->peer_transkey,                             //  Server short-term public key
               NULL,
               mpc_cert_secret_key_id (self->permacert));       //  Client long-term secret key

    //  Working variables for crypto calls
    size_t box_size = 128 + self->metadata_size;
    byte *plain = (byte *) malloc (box_size);
    byte *box = (byte *) malloc (box_size);

    //  Create Box [C + vouch + metadata](C'->S')
    memcpy (plain, mpc_cert_public_key (self->permacert), 32);
    memcpy (plain + 32, vouch_crypt, 96);
    memcpy (plain + 128, self->metadata_data, self->metadata_size);
    s_encrypt (self, initiate->nonce,
               plain, 128 + self->metadata_size,
               "CurveZMQINITIATE",
               NULL, NULL, NULL);                             // Use pre-computed session key
    free (plain);
    free (box);

    puts("Initiate sent");
    return command;
}

//  Returns 0 if OK, -1 if command or keys were invalid
static int
s_process_initiate (mpc_curve_codec_t *self, zframe_t *input)
{
    //  Working variables for crypto calls
    byte nonce [24];

    initiate_t *initiate = (initiate_t *) zframe_data (input);
    size_t metadata_size = zframe_size (input) - sizeof (initiate_t);
    size_t box_size = crypto_box_ZEROBYTES + 128 + metadata_size;
    byte *plain = (byte *) malloc (box_size);
    byte *box = (byte *) malloc (box_size);

    //  Check cookie is valid
    //  We could but don't expire cookie key after 60 seconds
    //  Cookie nonce is first 16 bytes of cookie
    memcpy (nonce, (byte *) "COOKIE--", 8);
    memcpy (nonce + 8, initiate->cookie, 16);
    //  Cookie box is next 80 bytes of cookie
    memset (box, 0, crypto_box_BOXZEROBYTES);
    memcpy (box + crypto_box_BOXZEROBYTES, initiate->cookie + 16, 80);
    int rc = crypto_secretbox_open (
        plain, box, crypto_box_BOXZEROBYTES + 80,
        nonce, self->cookie_key);

    //  Throw away the cookie key
    memset (self->cookie_key, 0, 32);
    if (rc == 0) {
        //  Check cookie plain text is as expected [C' + s']
        byte *cookie = plain + crypto_box_ZEROBYTES;
        if (memcmp (cookie, self->peer_transkey, 32)
        ||  memcmp (cookie + 32, zcert_secret_key (self->transcert), 32))
            rc = -1;
    }
    if (rc == 0)
        //  Open Box [C + vouch + metadata](C'->S')
        rc = s_decrypt (self,
            initiate->nonce,
            plain, 128 + metadata_size,
            "CurveZMQINITIATE",
            NULL, NULL, NULL);                              // Use pre-computed session key

    if (rc == 0) {
        memcpy (self->peer_permakey, plain, 32);
        if (s_authenticate_peer (self))
            rc = -1;            //  Authentication failed
    }
    if (rc == 0) {
        s_decode_metadata (self, plain + 128, metadata_size);

        //  Vouch nonce + box is 96 bytes at (plain + 32)
        byte vouch [96];
        memcpy (vouch, plain + 32, 96);
        rc = s_decrypt (self,
            vouch,
            plain, 64,
            "VOUCH---",
            self->peer_permakey,                            //  Server long-term public key
            (byte *)zcert_secret_key (self->transcert),     //  Client short-term secret key
            NULL);

        //  Check vouch is short term client public key plus our public key
        if (rc == 0 
        && (memcmp (plain, self->peer_transkey, 32)
        ||  memcmp (plain + 32, mpc_cert_public_key (self->permacert), 32)))
            rc = -1;
    }
    free (plain);
    free (box);
    puts("Initiate received");
    return rc;
}

static zframe_t *
s_produce_ready (mpc_curve_codec_t *self)
{
    //  Create serialized metdata data buffer ready to send
    s_encode_metadata (self);

    zframe_t *command = zframe_new (NULL, sizeof (ready_t) + self->metadata_size);
    ready_t *ready = (ready_t *) zframe_data (command);
    memcpy (ready->id, "\x05READY", 6);
    s_encrypt (self, ready->nonce,
               self->metadata_data, self->metadata_size,
               "CurveZMQREADY---",
               NULL, NULL, NULL);                           // Use pre-computed session key
    
    puts("Ready sent");
    return command;
}

//  Returns 0 if OK, -1 if command or keys were invalid
static int
s_process_ready (mpc_curve_codec_t *self, zframe_t *input)
{
    ready_t *ready = (ready_t *) zframe_data (input);
    size_t size = zframe_size (input) - sizeof (ready_t);
    byte *plain = (byte *) malloc (size);

    int rc = s_decrypt (self,
        ready->nonce,
        plain, size,
        "CurveZMQREADY---",
        NULL, NULL, NULL);                                 // Use pre-computed session key

    //  Metadata comprises entire box
    s_decode_metadata (self, plain, size);
    free (plain);
    puts("Ready received");
    return rc;
}

static zframe_t *
s_produce_message (mpc_curve_codec_t *self, zframe_t *clear)
{
    //  Our clear text consists of flags + message data
    size_t clear_size = zframe_size (clear) + 1;
    byte *clear_data = (byte *) malloc (clear_size);
    clear_data [0] = zframe_more (clear);
    memcpy (clear_data + 1, zframe_data (clear), zframe_size (clear));

    zframe_t *command = zframe_new (NULL, sizeof (message_t) + clear_size);
    message_t *message = (message_t *) zframe_data (command);
    memcpy (message->id, "\x07MESSAGE", 8);
    s_encrypt (self, message->nonce,
               clear_data, clear_size,
               self->is_server? "CurveZMQMESSAGES": "CurveZMQMESSAGEC",
               NULL, NULL, NULL);                         // Use pre-computed session key
    free (clear_data);

    puts("Message sent");
    return command;
}

static zframe_t *
s_process_message (mpc_curve_codec_t *self, zframe_t *input)
{
    message_t *message = (message_t *) zframe_data (input);
    size_t clear_size = zframe_size (input) - sizeof (message_t);
    byte *clear_data = (byte *) malloc (clear_size);
    int rc = s_decrypt (self,
        message->nonce,
        clear_data, clear_size,
        self->is_server? "CurveZMQMESSAGEC": "CurveZMQMESSAGES",
        NULL, NULL, NULL);                      // Use pre-computed session key

    zframe_t *clear = NULL;
    if (rc == 0) {
        //  Create frame with clear text
        clear = zframe_new (clear_data + 1, clear_size - 1);
        zframe_set_more (clear, clear_data [0]);
    }
    free (clear_data);
    puts("Message received");
    return clear;
}


//  Detect command type of frame
command_t
s_command (mpc_curve_codec_t *self, zframe_t *input)
{
    if (input) {
        size_t size = zframe_size (input);
        byte *data = zframe_data (input);
        if (size == sizeof (hello_t) && memcmp (data, "\x05HELLO", 6) == 0) {
            if (self->verbose)
                puts ("Received C:HELLO");
           return hello_command;
        }
        else
        if (size >= sizeof (initiate_t) && memcmp (data, "\x08INITIATE", 9) == 0) {
            if (self->verbose)
                puts ("Received C:INITIATE");
            return initiate_command;
        }
        else
        if (size == sizeof (welcome_t) && memcmp (data, "\x07WELCOME", 8) == 0) {
            if (self->verbose)
                puts ("Received S:WELCOME");
            return welcome_command;
        }
        else
        if (size >= sizeof (ready_t) && memcmp (data, "\x05READY", 6) == 0) {
            if (self->verbose)
                puts ("Received S:READY");
            return ready_command;
        }
        else
        if (size >= sizeof (message_t) && memcmp (data, "\x07MESSAGE", 8) == 0) {
            if (self->verbose)
                printf ("Received %c:MESSAGE\n", self->is_server? 'C': 'S');
            return message_command;
        }
    }
    return no_command;
}


static zframe_t *
s_execute_server (mpc_curve_codec_t *self, zframe_t *input)
{
    command_t command = s_command (self, input);
    if (self->state == expect_hello && command == hello_command) {
        if (s_process_hello (self, input) == 0) {
            self->state = expect_initiate;
            return s_produce_welcome (self);
        }
    }
    else
    if (self->state == expect_initiate && command == initiate_command) {
        s_precompute_key (self);
        if (s_process_initiate (self, input) == 0) {
            self->state = expect_message;
            return s_produce_ready (self);
        }
    }
    s_raise_exception (self, "Invalid command received from client");
    return NULL;
}

static zframe_t *
s_execute_client (mpc_curve_codec_t *self, zframe_t *input)
{
    command_t command = s_command (self, input);
    if (self->state == send_hello && command == no_command) {
        assert (zframe_size (input) == 32);
        memcpy (self->peer_permakey, zframe_data (input), 32);   // Copy server's long-term key into client's peer_permakey.
        self->state = expect_welcome;
        return s_produce_hello (self);
    }
    else
    if (self->state == expect_welcome && command == welcome_command) {
        if (s_process_welcome (self, input) == 0) {
            self->state = expect_ready;
            s_precompute_key (self);
            return s_produce_initiate (self);
        }
    }
    else
    if (self->state == expect_ready && command == ready_command) {
        if (s_process_ready (self, input) == 0) {
            self->state = expect_message;
            return NULL;
        }
    }
    s_raise_exception (self, "Invalid command received from server");
    return NULL;
}


//  --------------------------------------------------------------------------
//  Accept input command from peer. May return a frame to send to the peer,
//  or NULL if there is nothing to send.

zframe_t *
mpc_curve_codec_execute (mpc_curve_codec_t *self, zframe_t **input_p)
{
    assert (self);
    zframe_t *output = NULL;
    if (self->is_server)
        output = s_execute_server (self, *input_p);
    else
        output = s_execute_client (self, *input_p);

    zframe_destroy (input_p);
    return output;
}


//  --------------------------------------------------------------------------
//  Encode clear-text message to peer. Returns a frame ready to send
//  on the wire. Takes ownership of clear-text frame.

zframe_t *
mpc_curve_codec_encode (mpc_curve_codec_t *self, zframe_t **cleartext_p)
{
    assert (self);
    assert (self->state == expect_message);
    assert (cleartext_p);
    assert (*cleartext_p);

    zframe_t *encrypted = s_produce_message (self, *cleartext_p);
    zframe_destroy (cleartext_p);
    return encrypted;
}


//  --------------------------------------------------------------------------
//  Decode blob into message from peer. Takes ownership of encrypted frame.

zframe_t *
mpc_curve_codec_decode (mpc_curve_codec_t *self, zframe_t **encrypted_p)
{
    assert (self);
    assert (encrypted_p);
    assert (*encrypted_p);

    if (self->state == expect_message) {
        zframe_t *cleartext = NULL;
        if (s_command (self, *encrypted_p) == message_command)
            cleartext = s_process_message (self, *encrypted_p);
        else
            s_raise_exception (self, "Invalid command (expected MESSAGE)");
        zframe_destroy (encrypted_p);
        return cleartext;
    }
    else
    if (self->state == exception)
        return NULL;

    //  A bad state means the API is being misused
    assert (false);
}


//  --------------------------------------------------------------------------
//  Indicate whether handshake is still in progress

bool
mpc_curve_codec_connected (mpc_curve_codec_t *self)
{
    assert (self);
    return (self->state == expect_message);
}


//  --------------------------------------------------------------------------
//  Indicate whether codec hit a fatal error

bool
mpc_curve_codec_exception (mpc_curve_codec_t *self)
{
    assert (self);
    return (self->state == exception);
}


//  --------------------------------------------------------------------------
//  Returns metadata from peer, as a zhash table. The hash table remains
//  owned by the codec and the caller should not use it after destroying
//  the codec. Only valid after the peer has connected. NOTE: All keys
//  in the hash table are lowercase.

zhash_t *
mpc_curve_codec_metadata (mpc_curve_codec_t *self)
{
    assert (self);
    return (self->metadata_recd);
}


//  --------------------------------------------------------------------------
//  Selftest

//  @selftest
//  For the test case, we'll put the client and server certs into the
//  the same keystore file. This is not how it would work in real life.
//
//  The test case consists of the client sending a series of messages to
//  the server, which the server has to echo back. The client will send
//  both single and multipart messages. A message "END" signals the end
//  of the test.

#define TESTDIR "../certs"

static void *
server_task (void *args)
{
    bool verbose = *((bool *) args);
    //  Install the authenticator
    zctx_t *ctx = zctx_new ();
    zauth_t *auth = zauth_new (ctx);
    assert (auth);
    zauth_set_verbose (auth, verbose);
    zauth_configure_curve (auth, "*", TESTDIR);

    void *router = zsocket_new (ctx, ZMQ_ROUTER);
    int rc = zsocket_bind (router, "tcp://127.0.0.1:9004");
    assert (rc != -1);

    mpc_cert_t *cert = mpc_cert_load ("../certs/long-term/server.cert_secret"); //mpc_cert_load (TESTDIR "/server.cert");
    assert (cert);
    mpc_curve_codec_t *server = mpc_curve_codec_new_server (cert, ctx);
    assert (server);
    mpc_curve_codec_set_verbose (server, verbose);

    //  Set some metadata properties
    mpc_curve_codec_set_metadata (server, "Server", "CURVEZMQ/mpc_curve_codec");

    //  Execute incoming frames until ready or exception
    //  In practice we'd want a server instance per unique client
    while (!mpc_curve_codec_connected (server)) {
        zframe_t *sender = zframe_recv (router);
        zframe_t *input = zframe_recv (router);
        assert (input);
        zframe_t *output = mpc_curve_codec_execute (server, &input);
        assert (output);
        zframe_send (&sender, router, ZFRAME_MORE);
        zframe_send (&output, router, 0);
    }
    //  Check client metadata
    char *client_name = (char *) zhash_lookup (mpc_curve_codec_metadata (server), "client");
    assert (client_name);
    assert (streq (client_name, "CURVEZMQ/mpc_curve_codec"));

    bool finished = false;
    while (!finished) {
        //  Now act as echo service doing a full decode and encode
        zframe_t *sender = zframe_recv (router);
        zframe_t *encrypted = zframe_recv (router);
        assert (encrypted);
        zframe_t *cleartext = mpc_curve_codec_decode (server, &encrypted);
        assert (cleartext);
        if (memcmp (cleartext, "END", 3) == 0)
            finished = true;
        //  Echo message back
        encrypted = mpc_curve_codec_encode (server, &cleartext);
        assert (encrypted);
        zframe_send (&sender, router, ZFRAME_MORE);
        zframe_send (&encrypted, router, 0);
    }
    mpc_curve_codec_destroy (&server);
    mpc_cert_destroy (&cert);
    zauth_destroy (&auth);
    zctx_destroy (&ctx);
    return NULL;
}
//  @end

static void
x25519_key_exchange (
    byte *session_key,      //  Session key to be returned
    byte *public_key,       //  Public key to encrypt to, may be null
    byte *secret_key,       //  Private key to encrypt from, may be null
    char *secret_key_id)    //  Private key id to encrypt from, may be null  
{
    if(secret_key_id){
        //  If secret key id is present, run the protocol in MPC
        byte * session_key_b64 = kms_x25519(ACCESS_TOKEN, VAULT_ID, secret_key_id, public_key);
        byte* session_key_bytes = b64_decode(session_key_b64, strlen(session_key_b64));
        strcpy (session_key, session_key_bytes);
    }else{
         //  Otherwise, run the protocol from libsodium with secret key
        int res = crypto_scalarmult_curve25519(session_key, secret_key, public_key);
    }
}


void
mpc_curve_codec_test (bool verbose, char* access_token, char* vault_id)
{
    printf (" * mpc_curve_codec: ");

    //  Check compiler isn't padding our structures mysteriously
    assert (sizeof (hello_t) == 200);
    assert (sizeof (welcome_t) == 168);
    assert (sizeof (initiate_t) == 257);
    assert (sizeof (ready_t) == 30);
    assert (sizeof (message_t) == 32);

    //  @selftest
    //  Create temporary directory for test files
    
    zsys_dir_create (TESTDIR);
    
    zctx_t *ctx = zctx_new ();
    assert (ctx);
    void *dealer = zsocket_new (ctx, ZMQ_DEALER);
    int rc = zsocket_connect (dealer, "tcp://127.0.0.1:9004");
    assert (rc != -1);

    //  We'll create two long-term new certificates and save the client 
    //  public certificate on disk; in a real case we'd transfer this
    //  securely from the client machine to the server machine.            
    // =================================================> Use load to have benchmarks!
    /*
    char * server_lt_key_name = "server_long_term";
    mpc_cert_t *server_cert = mpc_cert_new (access_token, vault_id, server_lt_key_name);
    mpc_cert_save (server_cert, TESTDIR "/server.cert");
    puts("\n******** Server long-term *********\n");
    mpc_cert_print(server_cert);

    char * client_lt_key_name = "client_long_term";
    mpc_cert_t *client_cert = mpc_cert_new (access_token, vault_id, client_lt_key_name);
    //char *filename = (char *) malloc (strlen (TESTDIR) + 21);
    
    //sprintf (filename, TESTDIR "/client-%07d.cert", randof (10000000));
    mpc_cert_save_public (client_cert, TESTDIR "/client.cert_secret");
    puts("\n******** Client long-term *********\n");
    mpc_cert_print(client_cert);
    //free (filename);
    */
   mpc_cert_t *server_cert_lt = mpc_cert_load ("../certs/long-term/server.cert");     // => In server task
   mpc_cert_print(server_cert_lt);
   mpc_cert_t *client_cert_lt = mpc_cert_load ("../certs/long-term/client.cert");
   mpc_cert_print(client_cert_lt);

   zcert_t *server_cert_st = zcert_load ("../certs/short-term/server.cert");
   zcert_print(server_cert_st);
   zcert_t *client_cert_st = zcert_load ("../certs/short-term/client.cert");
   zcert_print(client_cert_st);

   byte session_key_1 [32]; // Purple key in MPC in server
   byte session_key_2 [32]; // Purple key in client
   byte session_key_3 [32]; 
   byte session_key_4 [32];

    // ========================================
    x25519_key_exchange (session_key_1,
            zcert_public_txt(client_cert_st),           // Client public key in txt
            NULL,
            mpc_cert_secret_key_id(server_cert_lt));     // Server secret key id 
    
    printf("Purple key in MPC in server: \n  ");
    print_in_bytes(session_key_1, 32);         

    // ========================================
    x25519_key_exchange (session_key_2,
            mpc_cert_public_key(server_cert_lt),        // Server Public key in bytes
            (byte *)zcert_secret_key(client_cert_st),  // Client Secrete key in bytes
            NULL);     
    printf("\nPurple key in client: \n  ");
    print_in_bytes(session_key_2, 32);   

    // ========================================
     x25519_key_exchange (session_key_3,
            zcert_public_txt(server_cert_st),           // Client public key in txt
            NULL,
            mpc_cert_secret_key_id(client_cert_lt));     // Server secret key id 
    
    printf("Vouch key in MPC in client: \n  ");
    print_in_bytes(session_key_3, 32);         

    // ========================================
    x25519_key_exchange (session_key_4,
            mpc_cert_public_key(client_cert_lt),        // Server Public key in bytes
            (byte *)zcert_secret_key(server_cert_st),  // Client Secrete key in bytes
            NULL);    
    printf("\nVouch key in server: \n  ");
    print_in_bytes(session_key_4, 32);   



    
    //  We'll run the server as a background task, and the
    //  client in this foreground thread.
    zthread_new (server_task, &verbose);

    //  Create a new client instance
    mpc_curve_codec_t *client = mpc_curve_codec_new_client (client_cert_lt);
    assert (client);
    mpc_curve_codec_set_verbose (client, verbose);

    //  Set some metadata properties
    mpc_curve_codec_set_metadata (client, "Client", "CURVEZMQ/mpc_curve_codec");
    mpc_curve_codec_set_metadata (client, "Identity", "E475DA11");

    //  Kick off client handshake
    //  First frame to new client is server's public key
    zframe_t *input = zframe_new (mpc_cert_public_key (server_cert_lt), 32);  // Client receives server's long-term public key
    zframe_t *output = mpc_curve_codec_execute (client, &input);           // Client produces HELLO box (+ sends his short-term public key)

    while (!mpc_curve_codec_connected (client)) {
        assert (output);
        rc = zframe_send (&output, dealer, 0);
        assert (rc >= 0);
        zframe_t *input = zframe_recv (dealer);
        assert (input);
        output = mpc_curve_codec_execute (client, &input);
    }
    
    //  Handshake is done, now try Hello, World
    zframe_t *cleartext = zframe_new ((byte *) "Hello, World", 12);
    zframe_t *encrypted = mpc_curve_codec_encode (client, &cleartext);
    assert (encrypted);
    zframe_send (&encrypted, dealer, 0);

    encrypted = zframe_recv (dealer);
    assert (encrypted);
    cleartext = mpc_curve_codec_decode (client, &encrypted);
    assert (cleartext);
    assert (zframe_size (cleartext) == 12);
    assert (memcmp (zframe_data (cleartext), "Hello, World", 12) == 0);
    zframe_destroy (&cleartext);

    //  Try a multipart message
    cleartext = zframe_new ((byte *) "Hello, World", 12);
    zframe_set_more (cleartext, 1);
    encrypted = mpc_curve_codec_encode (client, &cleartext);
    assert (encrypted);
    zframe_send (&encrypted, dealer, 0);
    cleartext = zframe_new ((byte *) "Second frame", 12);
    encrypted = mpc_curve_codec_encode (client, &cleartext);
    assert (encrypted);
    zframe_send (&encrypted, dealer, 0);

    encrypted = zframe_recv (dealer);
    assert (encrypted);
    cleartext = mpc_curve_codec_decode (client, &encrypted);
    assert (cleartext);
    assert (zframe_more (cleartext) == 1);
    zframe_destroy (&cleartext);

    encrypted = zframe_recv (dealer);
    assert (encrypted);
    cleartext = mpc_curve_codec_decode (client, &encrypted);
    assert (cleartext);
    assert (zframe_more (cleartext) == 0);
    zframe_destroy (&cleartext);

    //  Now send messages of increasing size, check they work
    int count;
    int size = 0;
    for (count = 0; count < 18; count++) {
        if (verbose)
            printf ("Testing message of size=%d...\n", size);

        cleartext = zframe_new (NULL, size);
        int byte_nbr;
        //  Set data to sequence 0...255 repeated
        for (byte_nbr = 0; byte_nbr < size; byte_nbr++)
            zframe_data (cleartext)[byte_nbr] = (byte) byte_nbr;

        encrypted = mpc_curve_codec_encode (client, &cleartext);
        assert (encrypted);
        zframe_send (&encrypted, dealer, 0);

        encrypted = zframe_recv (dealer);
        assert (encrypted);
        cleartext = mpc_curve_codec_decode (client, &encrypted);
        assert (cleartext);
        assert (zframe_size (cleartext) == size);
        for (byte_nbr = 0; byte_nbr < size; byte_nbr++) {
            assert (zframe_data (cleartext)[byte_nbr] == (byte) byte_nbr);
        }
        zframe_destroy (&cleartext);

        size = size * 2 + 1;
    }
    //  Signal end of test
    cleartext = zframe_new ((byte *) "END", 3);
    encrypted = mpc_curve_codec_encode (client, &cleartext);
    assert (encrypted);
    zframe_send (&encrypted, dealer, 0);

    encrypted = zframe_recv (dealer);
    assert (encrypted);
    cleartext = mpc_curve_codec_decode (client, &encrypted);
    assert (cleartext);
    zframe_destroy (&cleartext);

    mpc_cert_destroy (&server_cert_lt);
    mpc_cert_destroy (&client_cert_lt);
    mpc_curve_codec_destroy (&client);

    //  Some invalid operations to test exception handling
    server_cert_lt = mpc_cert_new (access_token, vault_id, "invalid_key");
    input = zframe_new (mpc_cert_public_key (server_cert_lt), 32);
    mpc_curve_codec_t *server = mpc_curve_codec_new_server (server_cert_lt, ctx);
    mpc_curve_codec_execute (server, &input);        // Client should produce HELLO, not server
    assert (mpc_curve_codec_exception (server));
    mpc_curve_codec_destroy (&server);
    mpc_cert_destroy (&server_cert_lt);

    zctx_destroy (&ctx);
    
    //  Delete all test files
    zdir_t *dir = zdir_new (TESTDIR, NULL);
    //zdir_remove (dir, true);
    zdir_destroy (&dir);
    //  @end

    //  Ensure server thread has exited before we do
    zclock_sleep (100);
    printf ("OK\n");
    
}
