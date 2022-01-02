#include <ulfius.h>

#ifndef HELPERS_H_   /* Include guard */
#define HELPERS_H_

typedef unsigned char   byte;           //  Single unsigned byte = 8 bits

/*
  * Helper functions
 */


/**
 * Concatenates two strings
 */
char* concat(const char *s1, const char *s2);

/**
 * Concatenates three strings
 */
char* concat3(const char *s1, const char *s2, const char *s3);

/**
 * Decode a u_map into a string
 */
char * print_map(const struct _u_map * map);

/**
 * Print the body of a response and return it in string
 */
char* print_body(struct _u_response * response);

/**
 * Print the complete response, including the protocol, the headers and the body
 */
void print_response(struct _u_response * response);

/**
 * Retrieve the private key's id from the content of the response
 */
char* get_key_id(char * response_body);

/**
* Retrieve the ECDH public key in z86 format from the content of the response
 */
char* get_ecdh_public_key_z85(char * response_body, char* key_id); 

/**
 * Retrieve the derived session key from the content of the response
 */
byte* get_session_key(char * response_body);

#endif // HELPERS_H_