#include <ulfius.h>

typedef struct _MPC_cert_t MPC_cert_t;
#define MPC_CERT_T_DEFINED


//  --------------------------------------------------------------------------
//  Encode a binary frame as a string; destination string MUST be at least
//  size * 5 / 4 bytes long plus 1 byte for the null terminator. Returns
//  dest. Size must be a multiple of 4.
char *
curve_z85_encode (char *dest, uint8_t *data, size_t size);
        

    
//  --------------------------------------------------------------------------
//  Decode an encoded string into a binary frame; dest must be at least
//  strlen (string) * 4 / 5 bytes long. Returns dest. strlen (string) 
//  must be a multiple of 5.
uint8_t *
curve_z85_decode (uint8_t *dest, char *string);



//  Constructor
MPC_cert_t * MPC_cert_new (char* access_token, char* vault_id, char* key_name);

//  Constructor, accepts public/secret key pair from caller
MPC_cert_t * MPC_cert_new_from (byte *public_key, char *secret_key_id);

//  Destructor
void MPC_cert_destroy (MPC_cert_t **self_p);

//  Return public part of key pair as 32-byte binary string
byte * MPC_cert_public_key (MPC_cert_t *self);

//  Return id of secret part of key pair as string
char * MPC_cert_secret_key_id (MPC_cert_t *self);

//  Return public part of key pair as Z85 armored string
char * MPC_cert_public_txt (MPC_cert_t *self);

//  Save full certificate (public + secret) to file for persistent storage
//  This creates one public file and one secret file (filename + "_secret").
int MPC_cert_save (MPC_cert_t *self, const char *filename);

//  Save public certificate only to file for persistent storage.
int MPC_cert_save_public (MPC_cert_t *self, const char *filename);

//  Save secret certificate only to file for persistent storage.
int MPC_cert_save_secret (MPC_cert_t *self, const char *filename);

//  Return true if two certificates have the same keys
int MPC_cert_eq (MPC_cert_t *self, MPC_cert_t *compare);

//  Print certificate contents to stdout
void MPC_cert_print (MPC_cert_t *self);

