/* Compile command:          gcc -L/usr/local/lib -o curve_mpc_handshake curve_mpc_handshake.c mpc/key_manager.c mpc/helpers.c mpc/MPC_cert.c -lcurve -lsodium -lzmq -lczmq -lulfius ${CFLAGS} ${LDFLAGS}
*/

#include <ulfius.h>
#include "curve_classes.h"
#include "zcert.h"
#include "../include/key_manager.h"
#include "../include/MPC_cert.h"

#define TESTDIR "../certs"

#define KEY_SIZE 32

/*Enter your bearer token here:*/
#define ACCESS_TOKEN ""

/*Enter your credentials here (i.e., PWDs and URLs of nodes):*/
#define CREDENTIALS_JSON ""

/*Enter your vault id here:*/
#define VAULT_ID ""


//  Encrypt a block of data using the connection nonce. If
//  key_to/key_from are null, uses precomputed key.
static int
s_encrypt (
    //curve_codec_t *self,    //  Codec instance sending the data
    byte *target,           //  target must be nonce + box
    byte *data,             //  Clear text data to encrypt
    size_t size,            //  Size of clear text data
    char *prefix,           //  Nonce prefix to use, 8 or 16 chars
    byte *key_to,           //  Public Key to encrypt to, may be null
    char *key_id_from,      //  Private Key id to encrypt from, may be null
    byte *key_from)         //  Private Key to encrypt from, may be null
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

    byte cookie_key [32];
    randombytes (cookie_key, 32);

    //  Prepare full nonce and store nonce into target
    //  Handle both short and long nonces
    byte nonce [24];
    if (strlen (prefix) == 16) {
        //  Long nonce is sequential integer
        memcpy (nonce, (byte *) prefix, 16);
        memcpy (nonce + 16, cookie_key, 8);
        target += 8;            //  Encrypted data comes after 8 byte nonce
    }
    else {
        //  Short nonce is random sequence
        randombytes (target, 16);
        memcpy (nonce, (byte *) prefix, 8);
        memcpy (nonce + 8, target, 16);
        target += 16;           //  Encrypted data comes after 16 byte nonce
    }

    //  Create box using either key pair, or precomputed key
    int rc;
    if(key_id_from){
        byte * session_key = kms_x25519(ACCESS_TOKEN, VAULT_ID, key_id_from, key_to);
    }else{
        rc = crypto_box (box, plain, box_size, nonce, key_to, key_from);
    }

    //  Now copy encrypted data into target; it will be 16 bytes longer than
    //  plain data
    //memcpy (target, box + crypto_box_BOXZEROBYTES, size + 16);
    //free (plain);
    //free (box);
    
    return rc;
}

int main (int argc, char **argv){

    //kms_hello(ACCESS_TOKEN, "Meret");
    kms_init_session(ACCESS_TOKEN, VAULT_ID, CREDENTIALS_JSON);

    //  Create temporary directory for test files
    zsys_dir_create (TESTDIR);

    /***********   Create client certificate without MPC   ***********/
    puts("******** Client *********\n");
    zcert_t *client_cert = zcert_new ();
    zcert_save (client_cert, TESTDIR "/client.cert");
    zcert_print(client_cert);

    byte * client_pk = zcert_public_key(client_cert); 
    printf("Client key into bytes: %s\n", (char*)client_pk);

    /***********   Create server certificate with MPC   ***********/
    puts("\n******** Server *********\n");

    char * key_name = "server_long_term";
    MPC_cert_t *server_cert_1 = MPC_cert_new(ACCESS_TOKEN, VAULT_ID, key_name);
    MPC_cert_save (server_cert_1, TESTDIR "/server.cert");
    MPC_cert_print(server_cert_1);


    char * key_name_2 = "server_long_term_2";
    MPC_cert_t *server_cert_2 = MPC_cert_new(ACCESS_TOKEN, VAULT_ID, key_name_2);
    MPC_cert_print(server_cert_2);

    byte signature [64];
    memset (signature, 0, 64);

    byte nonce [8];  

    s_encrypt (nonce,
               signature, 64,
               "CurveZMQHELLO---",
               (byte*)MPC_cert_public_txt(server_cert_1),     //  Public key in txt
               MPC_cert_secret_key_id(server_cert_2),         //  Secrete key id
               NULL);

    s_encrypt (nonce,
               signature, 64,
               "CurveZMQHELLO---",
               (byte*)MPC_cert_public_txt(server_cert_2),     //  Public key in txt
               MPC_cert_secret_key_id(server_cert_1),         //  Secrete key id
               NULL);           
    

   /***********   Destroy the certificates   ***********/
    zcert_destroy (&client_cert);
    MPC_cert_destroy (&server_cert_1);
    MPC_cert_destroy (&server_cert_2);

    return 0;
}