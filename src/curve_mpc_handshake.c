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

int main (int argc, char **argv){

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
    MPC_cert_t *server_cert = MPC_cert_new(ACCESS_TOKEN, VAULT_ID, key_name);
    MPC_cert_save (server_cert, TESTDIR "/server.cert");
    MPC_cert_print(server_cert);
    

   /***********   Destroy the certificates   ***********/
    zcert_destroy (&client_cert);
    MPC_cert_destroy (&server_cert);

    return 0;
}