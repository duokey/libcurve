/*  =========================================================================
    mpc_curve_library - contains all the include needed for CurveZMQ with MPC
    =========================================================================
*/

// Set up parameters to call DuoKey-KMS
/*Enter your bearer token here:*/
#define ACCESS_TOKEN "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiI1YmY2ZWJiYi0zY2RkLTQ1NTktOWY3NS1lOWFhZjM2ZTZjZjkiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jOGQwYmFhYS1hNWNjLTRjMGQtYmQ5My1jMTBjYWRmYzJkNzUvIiwiaWF0IjoxNjQxNDAwNTExLCJuYmYiOjE2NDE0MDA1MTEsImV4cCI6MTY0MTQwNDQxMSwiYWlvIjoiRTJaZ1lOaTcvc21OY3JZSmhuOHFyZSt3dEU3ZkFBQT0iLCJhcHBpZCI6IjViZjZlYmJiLTNjZGQtNDU1OS05Zjc1LWU5YWFmMzZlNmNmOSIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2M4ZDBiYWFhLWE1Y2MtNGMwZC1iZDkzLWMxMGNhZGZjMmQ3NS8iLCJvaWQiOiIwMmQzMDM0Zi1mMWQxLTRiOTAtODhhYS1kNmNiY2MwOWU1YjYiLCJyaCI6IjAuQVY0QXFyclF5TXlsRFV5OWs4RU1yZnd0ZGJ2cjlsdmRQRmxGbjNYcHF2TnViUGxlQUFBLiIsInN1YiI6IjAyZDMwMzRmLWYxZDEtNGI5MC04OGFhLWQ2Y2JjYzA5ZTViNiIsInRpZCI6ImM4ZDBiYWFhLWE1Y2MtNGMwZC1iZDkzLWMxMGNhZGZjMmQ3NSIsInV0aSI6IkZhVVBJWXZQcWt5aGE2U0k3QnI5QVEiLCJ2ZXIiOiIxLjAifQ.qj2C-hyxx46sqESPsJCf8wX19PPwv8G4o4gpU1Vn5karg-pmD3MVeO6XMQYX5d3tHJu5WSll95WElb2bkQv3WmZx4bPn5phVSTdDqczrSyl6KfUhdiyw7hswsGXW20589N7TlpmHIRa_wgZut5XXRaqLRKwCSSLEQl_3y6mukmjwDGk7KfeeOkG8pIdkE2_ilvShVKDFOnEp_sgVvtMgyPu67T3f9t8IN4ftV5VqLR6UYR0-C1cJVEe151Zq0eX1Hx87uw1S5Qqz8z0b-wdsnyTjDlvYD4EUcFC5EOucGMjbZrU2rlIk9GeayQ7W4dr8rxgA45JQvHf7aNnO0xfrGg"

/*Enter your credentials here (i.e., PWDs and URLs of nodes):*/
#define CREDENTIALS_JSON "ewogICJ1c2VySUQiOiAiNlppZ05LV0NWTzJad1lhWjZmQWtsNTlpdXZOcyIsCiAgInBhc3N3b3JkcyI6IFsKICAgICJSU3VoNWRPWms2UERLN1cxc1FrTlJSaW56SktwS0tFZnR0R0VyT2lmeUFTZyIsCiAgICAiSkQ1dnl6a210QmxEYmFmQjRLTW5jQUd5QmZBcHlac0lHWWZsZ1ZUWkJ3WEoiLAogICAgIjJ1aXVPcWxiTVVsTHFRNHI0Smt1dG5QVHp1MzNSbzlpUlVaR3M0aTVXWUJjIgogIF0sCiAgInVybHMiOiBbCiAgICAiaHR0cHM6Ly90c20tbm9kZTEuZHVva2V5LmNsb3VkIiwKICAgICJodHRwczovL3RzbS1ub2RlMi5kdW9rZXkuY2xvdWQiLAogICAgImh0dHBzOi8vdHNtLW5vZGUzLmR1b2tleS5jbG91ZCIKICBdCn0="

/*Enter your vault id here:*/
#define VAULT_ID "dc648dcd-e149-4e0b-6b78-08d8e3104952"

//  External dependencies
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <ulfius.h>

//  Opaque class structures to allow forward references
typedef struct _mpc_cert_t mpc_cert_t;
#define mpc_CERT_T_DEFINED
typedef struct _mpc_curve_codec_t mpc_curve_codec_t;
#define MPC_CURVE_CODEC_T_DEFINED

//  Public classes, each with its own header file
#include "../src/curve_classes.h"
#include "b64.h"
#include "curve_z85.h"
#include "helpers.h" 
#include "key_manager.h"
#include "mpc_cert.h"
#include "mpc_curve_codec.h" 



