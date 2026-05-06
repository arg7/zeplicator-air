/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "auth.h"
#include "db.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

char *auth_extract_cn(X509 *cert) {
    X509_NAME *subject = X509_get_subject_name(cert);
    if (!subject) return NULL;
    int idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (idx < 0) return NULL;
    X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, idx);
    if (!entry) return NULL;
    ASN1_STRING *asn1 = X509_NAME_ENTRY_get_data(entry);
    if (!asn1) return NULL;
    const unsigned char *data = ASN1_STRING_get0_data(asn1);
    int len = ASN1_STRING_length(asn1);
    char *cn = malloc((size_t)len + 1);
    if (!cn) return NULL;
    memcpy(cn, data, (size_t)len);
    cn[len] = '\0';
    return cn;
}

char *auth_cert_fingerprint(X509 *cert) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (!X509_digest(cert, EVP_sha256(), md, &md_len))
        return NULL;

    char *fp = malloc((size_t)md_len * 2 + 1);
    if (!fp) return NULL;
    for (unsigned int i = 0; i < md_len; i++)
        sprintf(fp + i * 2, "%02X", md[i]);
    fp[md_len * 2] = '\0';
    return fp;
}

static X509 *load_cert_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return NULL; }
    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    return cert;
}

static int verify_ca_signature(X509 *cert, X509_STORE *store) {
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) return -1;
    X509_STORE_CTX_init(ctx, store, cert, NULL);
    int rc = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    return rc == 1 ? 0 : -1;
}

err_t auth_load_ca_cert(const char *ca_path, X509_STORE **store_out) {
    X509_STORE *store = X509_STORE_new();
    if (!store) return ZEP_ERR_CERT;

    X509 *ca = load_cert_file(ca_path);
    if (!ca) { X509_STORE_free(store); return ZEP_ERR_CERT; }

    if (X509_STORE_add_cert(store, ca) != 1) {
        X509_free(ca);
        X509_STORE_free(store);
        return ZEP_ERR_CERT;
    }
    X509_free(ca);
    *store_out = store;
    return ZEP_ERR_OK;
}

err_t auth_init_server_ssl(const char *cert_path, const char *key_path,
                           const char *ca_path, void **ssl_ctx_out) {
    (void)cert_path; (void)key_path; (void)ca_path;
    *ssl_ctx_out = NULL;
    return ZEP_ERR_OK;
}

err_t auth_verify_client(sqlite3 *db, X509 *client_cert,
                         char *node_name, size_t len) {
    if (!client_cert) return ZEP_ERR_CERT;

    char *cn = auth_extract_cn(client_cert);
    if (!cn) {
        fprintf(stderr, "auth: failed to extract CN from client cert\n");
        return ZEP_ERR_CERT;
    }

    char *fp = auth_cert_fingerprint(client_cert);
    if (!fp) {
        fprintf(stderr, "auth: failed to compute fingerprint\n");
        free(cn);
        return ZEP_ERR_CERT;
    }

    char stored_fp[96] = {0};
    err_t ret = db_cert_lookup(db, cn, stored_fp, sizeof(stored_fp));

    if (ret == ZEP_ERR_OK) {
        if (strcasecmp(fp, stored_fp) != 0) {
            fprintf(stderr, "auth: fingerprint mismatch for CN=%s  (got=%s)\n", cn, fp);
            free(cn); free(fp);
            return ZEP_ERR_CERT;
        }
    } else {
        char *pem_data = NULL;
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            PEM_write_bio_X509(bio, client_cert);
            long pem_len = BIO_get_mem_data(bio, &pem_data);
            if (pem_len > 0 && pem_data) {
                db_cert_store(db, cn, fp, pem_data, "client", "", "");
            }
            BIO_free(bio);
        }
        fprintf(stderr, "auth: registered new cert CN=%s fp=%s\n", cn, fp);
    }

    snprintf(node_name, len, "%s", cn);
    free(cn);
    free(fp);
    return ZEP_ERR_OK;
}

err_t auth_verify_server_cert(X509 *server_cert, const char *expected_fqdn,
                              const char *ca_path) {
    if (!server_cert || !expected_fqdn || !ca_path)
        return ZEP_ERR_CERT;

    X509_STORE *store = NULL;
    if (auth_load_ca_cert(ca_path, &store) != ZEP_ERR_OK)
        return ZEP_ERR_CERT;

    if (verify_ca_signature(server_cert, store) != 0) {
        fprintf(stderr, "auth: server cert not signed by trusted CA\n");
        X509_STORE_free(store);
        return ZEP_ERR_CERT;
    }
    X509_STORE_free(store);

    char *cn = auth_extract_cn(server_cert);
    if (!cn) return ZEP_ERR_CERT;

    if (strcmp(cn, expected_fqdn) != 0) {
        fprintf(stderr, "auth: CN mismatch: expected=%s got=%s\n",
                expected_fqdn, cn);
        free(cn);
        return ZEP_ERR_CERT;
    }
    free(cn);
    return ZEP_ERR_OK;
}
