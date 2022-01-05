/* Compile command:          gcc -L/usr/local/lib -o curve_mpc_handshake curve_mpc_handshake.c mpc/key_manager.c mpc/helpers.c mpc/mpc_cert.c mpc/mpc_curve_codec.c b64/decode.c b64/buffer.c -lcurve -lsodium -lzmq -lczmq -lulfius ${CFLAGS} ${LDFLAGS}
*/

// ==============================================> Rename class main?
#include "../include/mpc_curve_library.h"

#define TESTDIR "../certs"
#define KEY_SIZE 32

//  Run a X25519 Key Exchange protocol from a public and secret key,
//  Return the symmetric key derived.
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

//  Generate an ECDH public-key pair in MPC, and another key-
//  pair without MPC.
//  Run two X25519 Key Exchange protocols, once with MPC from
//  a public key and secret key id, and once without MPC from
//  both a public and a secret key.
//  Show that both session key derived are indeed the same.
void test(){
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
    mpc_cert_t *server_cert = mpc_cert_new(ACCESS_TOKEN, VAULT_ID, key_name);
    mpc_cert_print(server_cert);
    mpc_cert_save (server_cert, TESTDIR "/server.cert");

    //char * txt = mpc_cert_get_public_txt(mpc_cert_public_key(server_cert));
    //printf("In txt: %s\n", txt);
    
    
    byte session_key_1 [KEY_SIZE]; 
    byte session_key_2 [KEY_SIZE]; 

    /***********   MPC Key Exchange   ***********/
    puts("\n******** MPC Key Exchange *********\n");
    x25519_key_exchange (session_key_1,
            zcert_public_txt(client_cert),           // Client public key in txt
            NULL,
            mpc_cert_secret_key_id(server_cert));     // Server secret key id 
    
    printf("Session key derived from (C, s) with MPC: \n  ");
    print_in_bytes(session_key_1, KEY_SIZE);         

    /***********   Key Exchange   ***********/
    puts("\n******** Key Exchange *********\n");
    x25519_key_exchange (session_key_2,
            mpc_cert_public_key(server_cert),        // Server Public key in bytes
            (byte *)zcert_secret_key(client_cert),  // Client Secrete key in bytes
            NULL);  

    
    printf("Session key derived from (c, S) without MPC: \n  ");
    print_in_bytes(session_key_2, KEY_SIZE);    

   if (memcmp (session_key_1, session_key_2, KEY_SIZE) == 0){
       puts("\n ====> Both keys are equal !");
   } else{
       puts("\n ====> Error: keys derived are different.");
   }

   /***********   Destroy the certificates   ***********/
    zcert_destroy (&client_cert);
    mpc_cert_destroy (&server_cert);
}

   
void create_certs(){

    /***********   Create long-term keys in MPC   ***********/

    mpc_cert_t *server_cert_lt = mpc_cert_new(ACCESS_TOKEN, VAULT_ID, "server_long_term");
    mpc_cert_save (server_cert_lt, "../certs/long-term/server.cert");
    mpc_cert_destroy (&server_cert_lt);

    mpc_cert_t *client_cert_lt = mpc_cert_new(ACCESS_TOKEN, VAULT_ID, "client_long_term");
    mpc_cert_save (client_cert_lt, "../certs/long-term/client.cert");
    mpc_cert_destroy (&client_cert_lt);

    /***********   Create short-term keys without MPC (czmq/libsodium)   ***********/

    zcert_t *server_cert_st = zcert_new ();
    zcert_save (server_cert_st, "../certs/short-term/server.cert");
    zcert_destroy (&server_cert_st);

    zcert_t *client_cert_st = zcert_new ();
    zcert_save (client_cert_st, "../certs/short-term/client.cert");
    zcert_destroy (&client_cert_st);
}    


int main (int argc, char **argv){

    //kms_hello(ACCESS_TOKEN, "Meret");
    // We do init session here for simplification. Session could also be initialized
    // in mpc_curve_codec_new_server and mpc_curve_codec_new_client.
    kms_init_session(ACCESS_TOKEN, VAULT_ID, CREDENTIALS_JSON);       
    

    //test();

    //create_certs();

    //curve_codec_test(true);
    
    // Session must already be initialized to run the handshake.
    mpc_curve_codec_test (true, ACCESS_TOKEN, VAULT_ID);   

    return 0;
}