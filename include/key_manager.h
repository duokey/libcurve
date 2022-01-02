
typedef unsigned char   byte;           //  Single unsigned byte = 8 bits

/**
 * Calls the kms to issue a hello to a given name, with a given token
 */
void kms_hello(char* access_token, char* name);

/**
 * Call the kms to init a session
 * Params: access_token: the bearer access token
 *         vault_id: the vault id
 *         credentials_json: the credentials of the user (i.e., PWDs and URLs of nodes)
 */
void kms_init_session(char* access_token, char* vault_id, char* credentials_json);

/**
 * Create a key.
 * Params: access_token: the bearer access token
 *         vault_id: the vault id
 *         key_name: the name you want to give to the key
 *         key_type: the type of the key. Supported for now: "RSA" and "ECDH"
 *         key_size: the size of the key. Supported for now: 1024 and 2048 for RSA, and 256 for ECDH         
 * Return: private key's id in string
 */
char* kms_create_key(char* access_token, char* vault_id, char* key_name, char* key_type, int key_size, char* curve_name);

/**
 * Get public key information, given a private key id.
 * Params: access_token: the bearer access token
 *         vault_id: the vault id
 *         key_type: the type of the key
 *         key_name: the name of the key
 *         key_id: the id of the key      
 * Return: public key in z85 string format, only in case of ECDH key type
 */
char* kms_get_public_key(char* access_token, char* vault_id, char* key_type, char* key_name, char* key_id);

/**
 * Run an X25519 ECDH Key Exchange, given a private key id and a public key.
 * Params: access_token: the bearer access token
 *         vault_id: the vault id
 *         private_key_id: the id of the private key
 *         public_key_z85: the public key in z85 format     
 * Return: derived symmetric session key in bytes
 */
byte* kms_x25519(char* access_token, char* vault_id, char* private_key_id, char* public_key_z85);