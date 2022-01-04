/*  =========================================================================
    mpc_cert - represent a certificate for an mpc ECDH public-key pair.

    It is adapted from CZMQ zcert certificates (http://czmq.zeromq.org).
    =========================================================================
*/

/*
    The mpc_cert class provides a way to create and work with security
    certificates for the ZMQ CURVE mechanism. A certificate contains a
    public + secret key pair, plus metadata. It can be used as a
    temporary object in memory, or persisted to disk. On disk, a
    certificate is stored as two files. One is public and contains only
    the public key. The second is secret and contains both the public key
    and the secret key id. The secret key itself is stored in mpc nodes
    and is not accessible in its entirety to anybody. The two certificates
    have the same filename, with the secret file adding "_secret".
    To exchange certificates, send the public file via some secure route.
    Certificates are not signed but are text files that can be verified by
    eye.
@discuss
    Certificates are stored in the ZPL (ZMQ RFC 4) format. They have two
    sections, "metadata" and "curve". The first contains a list of 'name =
    value' pairs, one per line. Values may be enclosed in quotes. The curve
    section has a 'public-key = keyvalue' and, for secret certificates, a
    'secret-key-id = keyid' line. The keyvalue is a Z85-encoded CURVE key.
@tbd
    Enable metadata.
@end
*/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ulfius.h>
#include "../curve_classes.h"
#include "../../include/key_manager.h"
// #include "../../include/helpers.h"        // Get rid once print_in_bytes no longer necessary
#include "../../include/mpc_cert.h"
#include "../../include/curve_z85.h"

struct _mpc_cert_t {
    byte* public_key;         //  Public key in binary
    char* secret_key_id;      //  Secret key in binary
    char* public_txt;         //  Public key in Z85 text
    //zhash_t *metadata;          //  Certificate metadata
    zconfig_t *config;            //  Config tree to save
};

//  --------------------------------------------------------------------------
//  Constructor
mpc_cert_t * mpc_cert_new (char* access_token, char* vault_id, char* key_name)
{
   byte public_key [32];

   char* secret_key_id = kms_create_key(access_token, vault_id, key_name, "ECDH", 256, "Curve25519");  // ED-25519    Curve25519
   char* public_txt = kms_get_public_key(access_token, vault_id, "ECDH", key_name, secret_key_id);
   
   curve_z85_decode (public_key, public_txt);

   return mpc_cert_new_from(public_key, secret_key_id);
}

//  Constructor, accepts public/secret key pair from caller
mpc_cert_t *
mpc_cert_new_from (byte *public_key, char *secret_key_id)
{
    mpc_cert_t *self = (mpc_cert_t *) malloc (sizeof (mpc_cert_t));
    if (!self)
        return NULL;

    self->public_key = malloc (sizeof (byte)* 32);
    self->secret_key_id = malloc (sizeof(char)* 28);
    self->public_txt = malloc (sizeof(char)*41);

    assert (public_key);
    assert (secret_key_id);

    memcpy (self->public_key, public_key, 32);
    strcpy (self->secret_key_id, secret_key_id);

    zmq_z85_encode (self->public_txt, self->public_key, 32);

    return self;
}


//  --------------------------------------------------------------------------
//  Destructor
void
mpc_cert_destroy (mpc_cert_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        mpc_cert_t *self = *self_p;
        zconfig_destroy (&self->config);
        free(self->public_key);
        free(self->secret_key_id);
        free(self->public_txt);
        free (self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Return public part of key pair as 32-byte binary string
byte *
mpc_cert_public_key (mpc_cert_t *self)
{
    assert (self);
    return self->public_key;
}


//  --------------------------------------------------------------------------
//  Return id of secret part of key pair as string
char *
mpc_cert_secret_key_id (mpc_cert_t *self)
{
    assert (self);
    return self->secret_key_id;
}


//  --------------------------------------------------------------------------
//  Return public part of key pair as Z85 armored string
char *
mpc_cert_public_txt (mpc_cert_t *self)
{
    assert (self);
    return self->public_txt;
}


//  --------------------------------------------------------------------------
//  Save full certificate (public + secret) to file for persistent storage
//  This creates one public file and one secret file (filename + "_secret").
int
mpc_cert_save (mpc_cert_t *self, const char *filename)
{
    assert (self);
    assert (filename);

    self->config = zconfig_new ("root", NULL);

    //  Save public certificate using specified filename
    mpc_cert_save_public (self, filename);

    //  Now save secret certificate using filename with "_secret" suffix
    char filename_secret [256];
    snprintf (filename_secret, 256, "%s_secret", filename);
    int rc = mpc_cert_save_secret (self, filename_secret);
    return rc;
}

//  --------------------------------------------------------------------------
//  Save public certificate only to file for persistent storage.
int
mpc_cert_save_public (mpc_cert_t *self, const char *filename)
{
    assert (self);
    assert (filename);

    zconfig_set_comment (self->config,
                         "   ZeroMQ CURVE Public Certificate");
    zconfig_set_comment (self->config,
                         "   Exchange securely, or use a secure mechanism to verify the contents");
    zconfig_set_comment (self->config,
                         "   of this file after exchange. Store public certificates in your home");
    zconfig_set_comment (self->config,
                         "   directory, in the .curve subdirectory.");

    zconfig_put (self->config, "/curve/public-key", self->public_txt);
    int rc = zconfig_save (self->config, filename);
    return rc;
}

//  --------------------------------------------------------------------------
//  Save public and secret certificates to file for persistent storage.
int
mpc_cert_save_secret (mpc_cert_t *self, const char *filename)
{
    assert (self);
    assert (filename);

    zconfig_set_comment (self->config,
                         "   ZeroMQ CURVE **Secret** Certificate");
    zconfig_set_comment (self->config,
                         "   DO NOT PROVIDE THIS FILE TO OTHER USERS nor change its permissions.");
    zconfig_put (self->config, "/curve/public-key", self->public_txt);
    zconfig_put (self->config, "/curve/secret-key-id", self->secret_key_id);

    zsys_file_mode_private ();
    int rc = zconfig_save (self->config, filename);
    zsys_file_mode_default ();
    return rc;
}


//  --------------------------------------------------------------------------
//  Return true if two certificates have the same keys
int
mpc_cert_eq (mpc_cert_t *self, mpc_cert_t *compare)
{
    assert (self);
    assert (compare);

    return (  streq (self->public_txt, compare->public_txt)
           && streq (self->secret_key_id, compare->secret_key_id));
}


//  --------------------------------------------------------------------------
//  Print certificate contents to stdout
void
mpc_cert_print (mpc_cert_t *self)
{
    assert (self);
    //zsys_info ("mpc_cert: metadata");

    //char secret_key_id [28];
    //memcpy (secret_key_id, self->secret_key_id, 28);

    
    /*puts("===========");
    printf ("mpc_cert:     public-key-txt = \"%s\"\n", self->public_txt);
    printf ("mpc_cert:     public-key-bytes = \"%s\"\n", (char*)self->public_key);
    //print_in_bytes(self->public_key, 32);
    printf ("mpc_cert:     secret-key-id = \"%s\"\n", self->secret_key_id);
    puts("===========");
    */

    zsys_info ("zcert:     public-key   = \"%s\"", self->public_txt);
    zsys_info ("zcert:     secret-key-id = \"%s\"", self->secret_key_id);
}


//    mpc_zcert_set_meta (cert, "email", "ph@imatix.com");


