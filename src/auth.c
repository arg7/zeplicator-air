/* MIT License — Copyright (c) 2026 CompEd Software Design srl — see LICENSE */

#include "auth.h"
#include "db.h"
#include "audit.h"
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


