/*  =========================================================================
    mpc_cert - represent a certificate for an mpc ECDH public-key pair.

    It is adapted from CZMQ zcert certificates (http://czmq.zeromq.org).
    =========================================================================
*/

#include <ulfius.h>

typedef struct _mpc_cert_t mpc_cert_t;
#define mpc_CERT_T_DEFINED

//  Constructor
mpc_cert_t * mpc_cert_new (char* access_token, char* vault_id, char* key_name);

//  Constructor, accepts public/secret key pair from caller
mpc_cert_t * mpc_cert_new_from (byte *public_key, char *secret_key_id);

//  Destructor
void mpc_cert_destroy (mpc_cert_t **self_p);

//  Return public part of key pair as 32-byte binary string
byte * mpc_cert_public_key (mpc_cert_t *self);

//  Return id of secret part of key pair as string
char * mpc_cert_secret_key_id (mpc_cert_t *self);

//  Return public part of key pair as Z85 armored string
char * mpc_cert_public_txt (mpc_cert_t *self);

//  Load certificate from file (constructor)
mpc_cert_t * mpc_cert_load (const char *filename);

//  Save full certificate (public + secret) to file for persistent storage
//  This creates one public file and one secret file (filename + "_secret").
int mpc_cert_save (mpc_cert_t *self, const char *filename);

//  Save public certificate only to file for persistent storage.
int mpc_cert_save_public (mpc_cert_t *self, const char *filename);

//  Save secret certificate only to file for persistent storage.
int mpc_cert_save_secret (mpc_cert_t *self, const char *filename);

//  Return true if two certificates have the same keys
int mpc_cert_eq (mpc_cert_t *self, mpc_cert_t *compare);

//  Print certificate contents to stdout
void mpc_cert_print (mpc_cert_t *self);

