#include <stdio.h>
#include <string.h>
#include <ulfius.h>
#include "../../include/helpers.h"

/*
key_manager.c runs REST API calls to DuoKey-KMS.

*/


#define BASE_URL "https://vault-kms.azurewebsites.net"
#define BEARER "bearer "

//typedef unsigned char   byte;           //  Single unsigned byte = 8 bits


/**
 * Call the kms to issue a hello to a given name, with a given token
 */
void kms_hello(char* access_token, char* name)
{
    struct _u_request request;
    struct _u_response response;

    /****************** Initialize the request ******************/
    ulfius_init_request(&request);

    // Create GET request to /hello endpoint.
    // Add the authorization bearer token.
    // Add the parameter name.
    ulfius_set_request_properties(&request,
                            U_OPT_HTTP_VERB, "GET",
                            U_OPT_HTTP_URL, BASE_URL,
                            U_OPT_HTTP_URL_APPEND, "/api/v1/kms/hello",
                            U_OPT_TIMEOUT, 20,
                            U_OPT_HEADER_PARAMETER, "Authorization", concat(BEARER, access_token),
                            U_OPT_URL_PARAMETER, "name", name,
                            U_OPT_NONE); // Required to close the parameters list


     /****************** Initialize the response ******************/
    ulfius_init_response(&response);
    ulfius_set_response_properties(&response,
                            U_OPT_HEADER_PARAMETER, "Content-Type", "application/json");

    /****************** Send the request ******************/
    int res = ulfius_send_http_request(&request, &response);

    /****************** Display the response body ******************/
    if (res == U_OK){
        print_body(&response);
    } else{
        printf("Error in http request: %d\n", res);
    }

    /****************** Clear the response and request pointers ******************/
    ulfius_clean_response(&response);
    ulfius_clean_request(&request);
}

/**
 * Call the kms to init a session
 * Params: access_token: the bearer access token
 *         vault_id: the vault id
 *         credentials_json: the credentials of the user (i.e., PWDs and URLs of nodes)
 */
void kms_init_session(char* access_token, char* vault_id, char* credentials_json)
{
    struct _u_request request;
    struct _u_response response;
    char body[2048];   // Large enough number for the request's body.

    /****************** Initialize the request ******************/
    ulfius_init_request(&request);

    // Create the body of the request.
    // For now, vaultType = "VaultTypeSepior", and authType = "SharedSecret"
    snprintf(body, sizeof(body), "{             \
        \"vaultId\": \"%s\",                    \
        \"vaultType\": \"VaultTypeSepior\",     \
        \"authType\": \"SharedSecret\",         \
        \"credentialsJson\": \"%s\"\n}", vault_id, credentials_json);  
    
    // Create POST request to /init endpoint.
    // Add the authorization bearer token.
    // Add the body.
    ulfius_set_request_properties(&request,
                            U_OPT_HTTP_VERB, "POST",
                            U_OPT_HTTP_URL, BASE_URL,
                            U_OPT_HTTP_URL_APPEND, "/api/v1/kms/sys/session/init",
                            U_OPT_HEADER_PARAMETER, "Content-Type", "application/json",
                            U_OPT_TIMEOUT, 20,
                            U_OPT_HEADER_PARAMETER, "Authorization", concat(BEARER, access_token),
                            U_OPT_STRING_BODY, body,
                            U_OPT_NONE); // Required to close the parameters list


     /****************** Initialize the response ******************/
    ulfius_init_response(&response);
    ulfius_set_response_properties(&response,
                            U_OPT_HEADER_PARAMETER, "Content-Type", "application/json");

    /****************** Send the request ******************/
    int res = ulfius_send_http_request(&request, &response);

    /****************** Display the response body ******************/
    if (res == U_OK){
        print_body(&response);
    } else{
        printf("Error in http request: %d\n", res);
    }

    /****************** Clear the response and request pointers ******************/
    ulfius_clean_response(&response);
    ulfius_clean_request(&request);
}

/**
 * Create a key.
 * Params: access_token: the bearer access token
 *         vault_id: the vault id
 *         key_name: the name you want to give to the key
 *         key_type: the type of the key. Supported for now: "RSA" and "ECDH"
 *         key_size: the size of the key. Supported for now: 1024 and 2048 for RSA, and 256 for ECDH         
 * Return: private key's id in string
 */
char* kms_create_key(char* access_token, char* vault_id, char* key_name, char* key_type, int key_size, char* curve_name)
{
    struct _u_request request;
    struct _u_response response;
    char body[8096];   // Large enough number for the request's body.

    /****************** Initialize the request ******************/
    ulfius_init_request(&request);

    // Create the body of the request. For now, only name, size, and type are dealt
    // with, the other parameters are ignored.
   snprintf(body, sizeof(body), "{      \
       \"vaultId\": \"%s\",             \
       \"attributes\": {                \
           \"id\": \"\",                \
           \"name\": \"%s\",            \
           \"description\": \"creating a new key\", \
           \"size\": %d,                \
           \"type\": \"%s\",            \
           \"vaultId\": \"%s\",         \
           \"publicKey\": \"string\",   \
           \"curveName\": \"%s\", \
           \"enabled\": \"string\",     \
           \"state\": 0,                \
           \"activationTime\": \"2021-05-26T04:37:20.440Z\",    \
           \"isDecrypt\": true,         \
           \"isEncrypt\": true,         \
           \"isWrap\": true,            \
           \"isUnwrap\": true,          \
           \"isDeriveKey\": true,       \
           \"isMacGenerate\": true,     \
           \"isMacVerify\": true,       \
           \"isAppManageable\": true,   \
           \"isSign\": true,            \
           \"isVerify\": true,          \
           \"isAgreeKey\": true,        \
           \"isExport\": true,          \
           \"isAuditLogEnable\": true,  \
           \"deactivationTime\": \"2021-05-26T04:37:20.440Z\",  \
           \"reason\": 0,               \
           \"compromiseTime\": \"2021-05-26T04:37:20.440Z\",    \
           \"comment\": \"string\",     \
           \"publishPublicKey\": true,  \
           \"externalId\": \"string\"}  \
           \n}", vault_id, key_name, key_size, key_type, vault_id, curve_name); 
    
    // Create POST request to /init endpoint.
    // Add the authorization bearer token.
    // Add the body.
    ulfius_set_request_properties(&request,
                            U_OPT_HTTP_VERB, "POST",
                            U_OPT_HTTP_URL, BASE_URL,
                            U_OPT_HTTP_URL_APPEND, "/api/v1/kms/key/create_edit",
                            U_OPT_HEADER_PARAMETER, "Content-Type", "application/json",
                            U_OPT_TIMEOUT, 20,
                            U_OPT_HEADER_PARAMETER, "Authorization", concat(BEARER, access_token),
                            U_OPT_STRING_BODY, body,
                            U_OPT_NONE); // Required to close the parameters list


     /****************** Initialize the response ******************/
    ulfius_init_response(&response);
    ulfius_set_response_properties(&response,
                            U_OPT_HEADER_PARAMETER, "Content-Type", "application/json");

    /****************** Send the request ******************/
    int res = ulfius_send_http_request(&request, &response);

    /****************** Display the response body and retrieve the private key's id ******************/
    if (res == U_OK){
        char* body =  print_body(&response);
        char* key_id = get_key_id(body);
        return key_id;
    } else{
        printf("Error in http request: %d\n", res);
        return "";
    }

    /****************** Clear the response and request pointers ******************/
    ulfius_clean_response(&response);
    ulfius_clean_request(&request);
}


/**
 * Get public key information, given a private key id.
 * Params: access_token: the bearer access token
 *         vault_id: the vault id
 *         key_type: the type of the key
 *         key_name: the name of the key
 *         key_id: the id of the key      
 * Return: public key in z85 string format, only in case of ECDH key type
 */
char* kms_get_public_key(char* access_token, char* vault_id, char* key_type, char* key_name, char* key_id)
{
    struct _u_request request;
    struct _u_response response;

    /****************** Initialize the request ******************/
    ulfius_init_request(&request);
 
    
    // Create GET request to /get_key endpoint.
    // Add the authorization bearer token.
    // Add the parameters.
    ulfius_set_request_properties(&request,
                            U_OPT_HTTP_VERB, "GET",
                            U_OPT_HTTP_URL, BASE_URL,
                            U_OPT_HTTP_URL_APPEND, "/api/v1/kms/key/:keyId/get_key",
                            U_OPT_TIMEOUT, 20,
                            U_OPT_HEADER_PARAMETER, "Authorization", concat(BEARER, access_token),
                            U_OPT_URL_PARAMETER, "keyId", key_id,
                            U_OPT_URL_PARAMETER, "vaultId", vault_id,
                            U_OPT_URL_PARAMETER, "keyLabel", key_name,
                            U_OPT_NONE); // Required to close the parameters list

     /****************** Initialize the response ******************/
    ulfius_init_response(&response);
    ulfius_set_response_properties(&response,
                            U_OPT_HEADER_PARAMETER, "Content-Type", "application/json");

    /****************** Send the request ******************/
    int res = ulfius_send_http_request(&request, &response);

    /****************** Display the response body and retrieve the ECDH public key ******************/
    char* public_key_z85 = "";

    if (res == U_OK){
        char* body = print_body(&response);
        
        if (strcmp(key_type, "ECDH") == 0){
            public_key_z85 = get_ecdh_public_key_z85(body, key_id); //get_ecdh_public_key_z85(&response, key_id);
        }
    } else{
        printf("Error in http request: %d\n", res);
    }
    return public_key_z85;

    /****************** Clear the response and request pointers ******************/
    ulfius_clean_response(&response);
    ulfius_clean_request(&request);
}

/**
 * Run an X25519 ECDH Key Exchange, given a private key id and a public key.
 * Params: access_token: the bearer access token
 *         vault_id: the vault id
 *         private_key_id: the id of the private key
 *         public_key_z85: the public key in z85 format     
 * Return: derived symmetric session key in bytes
 */
byte* kms_x25519(char* access_token, char* vault_id, char* private_key_id, char* public_key_z85)
{
    struct _u_request request;
    struct _u_response response;
    char body[200];   // Large enough number for the request's body.

    //char* private_key_id = "IgbPAcHuPHnIBeXHspdJuq6fKzMt";
    //char* public_key_z85 = "vKn7>SXFSUiu&Ec13PUU-Jx/(ucf#g81iAB62X=H";

    puts("In key manager:");


    /****************** Initialize the request ******************/
    ulfius_init_request(&request);

    // Create the body of the request. For now, only name, size, and type are dealt
    // with, the other parameters are ignored.
   snprintf(body, sizeof(body), "{      \
       \"vaultId\": \"%s\",             \
       \"publicKeyZ85\": \"%s\",        \
       \"alg\": \"X25519\"}", vault_id, public_key_z85); 

    
    // Create POST request to /key_exchange endpoint.
    // Add the authorization bearer token.
    // Add the body.
    ulfius_set_request_properties(&request,
                            U_OPT_HTTP_VERB, "POST",
                            U_OPT_HTTP_URL, BASE_URL,
                            U_OPT_HTTP_URL_APPEND, concat3("/api/v1/kms/key/", private_key_id, "/key_exchange"),
                            U_OPT_HEADER_PARAMETER, "Content-Type", "application/json",
                            U_OPT_HEADER_PARAMETER, "Accept", "application/json",
                            U_OPT_TIMEOUT, 20,
                            U_OPT_HEADER_PARAMETER, "Authorization", concat(BEARER, access_token),
                            U_OPT_STRING_BODY, body,
                            U_OPT_NONE); // Required to close the parameters list


     /****************** Initialize the response ******************/
    ulfius_init_response(&response);
    //ulfius_set_response_properties(&response,
    //                        U_OPT_HEADER_PARAMETER, "Content-Type", "application/json");

    /****************** Send the request ******************/
    puts("C");
    int res = ulfius_send_http_request(&request, &response);

    /****************** Display the response body and retrieve the private key's id ******************/
    puts("D");
    if (res == U_OK){
        char* body =  print_body(&response);
        byte* session_key = get_session_key(body);
        return session_key;
    } else{
        printf("Error in http request: %d\n", res);
        return "";
    }

    /****************** Clear the response and request pointers ******************/
    ulfius_clean_response(&response);
    ulfius_clean_request(&request);
}


/*
    #include <jansson.h>

    json_t* json_body = json_object();
   
    json_object_set_new(json_body, "vauldId", json_string(vault_id));

    json_t * vault_id_json = json_object_get(json_body, "vauldId");
    if (!json_is_string(vault_id_json)){
        fprintf(stderr, "error: sha is not a string\n");
    } else{
        printf("%s\n", json_string_value(vault_id_json));
    }
    printf("%ld\n",    json_object_size(json_body)); */
   