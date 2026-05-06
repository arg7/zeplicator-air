/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#ifndef ZEP_AIR_AUTH_H
#define ZEP_AIR_AUTH_H

#include "common.h"
#include <sqlite3.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

err_t auth_load_ca_cert(const char *ca_path, X509_STORE **store);

err_t auth_init_server_ssl(const char *cert_path, const char *key_path,
                           const char *ca_path,
                           void **ssl_ctx_out);

err_t auth_verify_client(sqlite3 *db, X509 *client_cert, char *node_name, size_t len);

char *auth_extract_cn(X509 *cert);

char *auth_cert_fingerprint(X509 *cert);

err_t auth_verify_server_cert(X509 *server_cert, const char *expected_fqdn,
                              const char *ca_path);

#endif
