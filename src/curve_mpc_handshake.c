/* Compile command:          gcc -L/usr/local/lib -o curve_mpc_handshake curve_mpc_handshake.c mpc/key_manager.c mpc/helpers.c mpc/MPC_cert.c b64/decode.c b64/buffer.c -lcurve -lsodium -lzmq -lczmq -lulfius ${CFLAGS} ${LDFLAGS}
*/

#include <ulfius.h>
#include "curve_classes.h"
#include "zcert.h"
#include "../include/key_manager.h"
#include "../include/MPC_cert.h"
#include "../include/helpers.h"    // Get rid once print_in_bytes no longer necessary
#include "../include/b64.h"

#define TESTDIR "../certs"

#define KEY_SIZE 32

#define crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES 32U

/*Enter your bearer token here:*/
#define ACCESS_TOKEN ""

/*Enter your credentials here (i.e., PWDs and URLs of nodes):*/
#define CREDENTIALS_JSON ""

/*Enter your vault id here:*/
#define VAULT_ID ""

//  Run a X25519 Key Exchange protocol from a public and secret key.
//  Return the symmetric key derived.
static void
x25519_key_exchange (
    byte *session_key,      //  session key to be returned
    byte *public_key,       //  Public Key to encrypt to, may be null
    char *secret_key_id,    //  Private Key id to encrypt from, may be null
    byte *secret_key)       //  Private Key to encrypt from, may be null
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

    /***********   Create server certificate with MPC   ***********/
    puts("\n******** Server *********\n");
    char * key_name = "server_long_term";
    MPC_cert_t *server_cert = MPC_cert_new(ACCESS_TOKEN, VAULT_ID, key_name);
    MPC_cert_save (server_cert, TESTDIR "/server.cert");
    MPC_cert_print(server_cert);
    
    byte session_key_1 [KEY_SIZE]; 
    byte session_key_2 [KEY_SIZE]; 

    /***********   MPC Key Exchange   ***********/
    puts("\n******** MPC Key Exchange *********\n");
    x25519_key_exchange (session_key_1,
            zcert_public_txt(client_cert),           // Client public key in txt
            MPC_cert_secret_key_id(server_cert),     // Server secret key id
            NULL);   
    
    printf("Session key derived from (C, s) with MPC: \n  ");
    print_in_bytes(session_key_1, KEY_SIZE);         

    /***********   Key Exchange   ***********/
    puts("\n******** Key Exchange *********\n");
    x25519_key_exchange (session_key_2,
            MPC_cert_public_key(server_cert),        // Server Public key in bytes
            NULL,     // Server secret key id
            (byte *)zcert_secret_key(client_cert));  // Client Secrete key in bytes

    
    printf("Session key derived from (c, S) without MPC: \n  ");
    print_in_bytes(session_key_2, KEY_SIZE);    

   if (memcmp (session_key_1, session_key_2, KEY_SIZE) == 0){
       puts("\n ====> Both keys are equal !");
   } else{
       puts("\n ====> Error: keys derived are different.");
   }  


   /***********   Destroy the certificates   ***********/
    zcert_destroy (&client_cert);
    MPC_cert_destroy (&server_cert);

    return 0;
}