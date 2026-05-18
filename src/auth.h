/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_AUTH_H
#define ZEP_AIR_AUTH_H

#include "common.h"
#include <sqlite3.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

err_t auth_load_ca_cert(const char *ca_path, X509_STORE **store);

char *auth_extract_cn(X509 *cert);

char *auth_cert_fingerprint(X509 *cert);

#endif
