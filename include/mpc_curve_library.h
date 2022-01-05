/*  =========================================================================
    mpc_curve_library - contains all the include needed for CurveZMQ with MPC
    =========================================================================
*/

// Set up parameters to call DuoKey-KMS
/*Enter your bearer token here:*/
#define ACCESS_TOKEN ""

/*Enter your credentials here (i.e., PWDs and URLs of nodes):*/
#define CREDENTIALS_JSON ""

/*Enter your vault id here:*/
#define VAULT_ID ""

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



