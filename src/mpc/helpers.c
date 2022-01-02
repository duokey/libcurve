#include <stdio.h>
#include <string.h>

#include "../../include/helpers.h"

 /*
  * Helper functions
 */

/**
 * Concatenates two strings
 */
char* concat(const char *s1, const char *s2)
{
    const size_t len1 = strlen(s1);
    const size_t len2 = strlen(s2);
    char *result = malloc(len1 + len2 + 1); // +1 for the null-terminator
    // in real code you would check for errors in malloc here
    memcpy(result, s1, len1);
    memcpy(result + len1, s2, len2 + 1); // +1 to copy the null-terminator
    return result;
}

/**
 * Concatenates three strings
 */
char* concat3(const char *s1, const char *s2, const char *s3)
{
    return concat(concat(s1, s2), s3);
}

/**
 * Decode a u_map into a string
 */
char * print_map(const struct _u_map * map) {
  char * line, * to_return = NULL;
  const char **keys;
  int len, i;
  if (map != NULL) {
    keys = u_map_enum_keys(map);
    for (i=0; keys[i] != NULL; i++) {
      len = snprintf(NULL, 0, "key is %s, value is %s\n", keys[i], u_map_get(map, keys[i]));
      line = malloc((len+1)*sizeof(char));
      snprintf(line, (len+1), "key is %s, value is %s\n", keys[i], u_map_get(map, keys[i]));
      if (to_return != NULL) {
        len = strlen(to_return) + strlen(line) + 1;
        to_return = realloc(to_return, (len+1)*sizeof(char));
      } else {
        to_return = malloc((strlen(line) + 1)*sizeof(char));
        to_return[0] = 0;
      }
      strcat(to_return, line);
      free(line);
    }
    return to_return;
  } else {
    return NULL;
  }
}

/**
 * Print the body of a response and return it in string
 */
char* print_body(struct _u_response * response){
    if (response != NULL) {
        char *response_body = malloc (sizeof (size_t) * response->binary_body_length+1);
        //char response_body[response->binary_body_length + 1];    // array of length of response size
        strncpy(response_body, response->binary_body, response->binary_body_length);
        response_body[response->binary_body_length] = '\0';
        printf("\n%s\n\n", response_body);

        return response_body;
  }
}

/**
 * Print the complete response, including the protocol, the headers and the body
 */
void print_response(struct _u_response * response) {
  if (response != NULL) {
    char * headers = print_map(response->map_header);
    printf("protocol is\n%s\n\n  headers are \n%s\n\n",
           response->protocol, headers);
    print_body(response);
    free(headers);
  }
}

/**
 * Retrieve string sub from str
 */
char *strremove(char *str, const char *sub) {
    size_t len = strlen(sub);
    if (len > 0) {
        char *p = str;
        size_t size = 0;
        while ((p = strstr(p, sub)) != NULL) {
            size = (size == 0) ? (p - str) + strlen(p + len) + 1 : size - len;
            memmove(p, p + len, size - (p - str));
        }
    }
    return str;
}

/**
 * Retrieve the private key's id from the content of the response
 */
char* get_key_id(char * response_body) {
  if (response_body != ""){
  
        char* key_id = strremove(response_body, "{\"keyId\":\"");
        key_id = strremove(key_id, "\"}");

        return key_id;
  }
}


/**
 * Retrieve the ECDH public key in z86 format from the content of the response
 */
char* get_ecdh_public_key_z85(char* response_body, char* key_id) {
   if (response_body != "") {

        char* public_key_z85 = strremove(response_body, concat3("{\"kty\":\"ECDH\", \"n\":\"\", \"e\":0, \"alg\":\"X25519\", \"kid\":\"", key_id, "\", \"publicKeyZ85\":\""));
        public_key_z85 = strremove(public_key_z85, "\"}");

        return public_key_z85;
  }
}


/**
 * Retrieve the derived session key from the content of the response
 */
byte* get_session_key(char * response_body) {
   if (response_body != "") {

        char* session_key = strremove(response_body, "{\"sessionKey\":\"");
        session_key = strremove(session_key, "\"}");

        return session_key;
  }
}
