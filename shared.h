#ifndef SHARED_H
#define SHARED_H
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define BUFSIZE 1500
#define PORT 1337
#define DTLS_MTU 1500

/** Context for custom UDP BIO */
typedef struct {
    int sockfd;
    struct sockaddr_storage peer;
    socklen_t peer_len;
} BIO_UDP_CTX;

/* UDP send wrapper */
static int udp_send(BIO_UDP_CTX *ctx, const char *data, int len) {
    return sendto(ctx->sockfd, data, len, 0,
                  (struct sockaddr*)&ctx->peer, ctx->peer_len);
}

/* UDP receive wrapper */
static int udp_receive(BIO_UDP_CTX *ctx, char *data, int len) {
    int ret = recvfrom(ctx->sockfd, data, len,
                       0, NULL, NULL);
    return ret;
}

static int udp_bio_create(BIO *b) {
    BIO_set_init(b, 1);
    BIO_set_data(b, NULL);
    return 1;
}
static int udp_bio_destroy(BIO *b) {
    BIO_UDP_CTX *ctx = BIO_get_data(b);
    free(ctx);
    BIO_set_data(b, NULL);
    BIO_set_init(b, 0);
    return 1;
}
static int udp_bio_read(BIO *b, char *buf, int len) {
    BIO_UDP_CTX *ctx = BIO_get_data(b);
    if (!ctx) return 0;

    int ret = udp_receive(ctx, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) BIO_set_retry_read(b);
        return -1;
    }
    if (ret == 0) return 0;

    return ret;
}
static int udp_bio_write(BIO *b, const char *in, int inlen) {
    BIO_UDP_CTX *ctx = BIO_get_data(b);
    if (!ctx) return 0;
    int sent = udp_send(ctx, in, inlen);
    if (sent < 0) BIO_set_retry_write(b);
    return sent;
}
static long udp_bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
    BIO_UDP_CTX *ctx = BIO_get_data(b);
    switch (cmd) {
    case BIO_CTRL_FLUSH:
        return 1;
    case BIO_CTRL_DGRAM_SET_CONNECTED:
        memcpy(&ctx->peer, ptr, sizeof(ctx->peer));
        ctx->peer_len = sizeof(ctx->peer);
        return 1;
    case BIO_CTRL_DGRAM_QUERY_MTU:
        return DTLS_MTU;
    default:
        return 0;
    }
}
static void init_udp_bio(BIO_METHOD **udp_bio_method) {
    if (*udp_bio_method) return;
    *udp_bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "udp");
    BIO_meth_set_create(*udp_bio_method, udp_bio_create);
    BIO_meth_set_destroy(*udp_bio_method, udp_bio_destroy);
    BIO_meth_set_read(*udp_bio_method, udp_bio_read);
    BIO_meth_set_write(*udp_bio_method, udp_bio_write);
    BIO_meth_set_ctrl(*udp_bio_method, udp_bio_ctrl);
}

int set_key_and_certificate(SSL_CTX* ssl_ctx) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    if ((pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL) {
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        goto cleanup;
    }


    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    if ((x509 = X509_new()) == NULL) {
        goto cleanup;
    }

    if (!X509_set_version(x509, 2)) {
        goto cleanup;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    if (!X509_gmtime_adj(X509_get_notBefore(x509), 0)) {
        goto cleanup;
    }
    if (!X509_gmtime_adj(X509_get_notAfter(x509), 31536000L)) { // 365 days in seconds
        goto cleanup;
    }

    if (!X509_set_pubkey(x509, pkey)) {
        goto cleanup;
    }


    X509_NAME *name = X509_get_subject_name(x509);
    if (name == NULL) {
        goto cleanup;
    }
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0)) {
        goto cleanup;
    }
    if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"MyOrganization", -1, -1, 0)) {
        goto cleanup;
    }

    if (!X509_set_issuer_name(x509, name)) {
        goto cleanup;
    }

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        goto cleanup;
    }

    if (!SSL_CTX_use_certificate(ssl_ctx, x509)) {
        printf("\n A \n");
        goto cleanup;
    }

    if (!SSL_CTX_use_PrivateKey(ssl_ctx, pkey)) {
        goto cleanup;
    }

    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        goto cleanup;
    }

    ret = 1;

cleanup:
    if (ret != 1)
        ERR_print_errors_fp(stderr);
    if (x509)
        X509_free(x509);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);

    return ret;
}

int openssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    return 1;
}

// Add this new callback function near other OpenSSL helper functions
void dtls_info_callback(const SSL *ssl, int where, int ret) {
    const char *direction = "";
    const char *method = "undefined";
    if (where & SSL_CB_READ) {
        direction = "Received";
    } else if (where & SSL_CB_WRITE) {
        direction = "Sent";
    }

    if (where & SSL_ST_CONNECT)
        method = "SSL_connect";
    else if (where & SSL_ST_ACCEPT)
        method = "SSL_accept";
    
    if (where & SSL_CB_LOOP) {
        printf("DTLS: Info method=%s state=%s(%s), where=%d, ret=%d\n",
            method, SSL_state_string(ssl), SSL_state_string_long(ssl), where, ret);
    } else if (where & SSL_CB_ALERT) {
        method = (where & SSL_CB_READ) ? "read":"write";
        printf("DTLS: Alert method=%s state=%s(%s), where=%d, ret=%d\n",
            method, SSL_state_string(ssl), SSL_state_string_long(ssl), where, ret);
    }
}

// In create_ssl_session_and_bio function, add the callback registration
int create_ssl_session_and_bio(SSL **ssl) {
    SSL_CTX* ssl_ctx = NULL;
    BIO *bio = NULL;
    /* Custom BIO methods */
    static BIO_METHOD *udp_bio_method = NULL;

    /* Initialize custom UDP BIO method */
    init_udp_bio(&udp_bio_method);

    if ((ssl_ctx = SSL_CTX_new(DTLS_method())) == NULL) {
        return 0;
    }

    // Add this line to set the info callback
    SSL_CTX_set_info_callback(ssl_ctx, dtls_info_callback);

    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, openssl_verify_callback);

    if (!set_key_and_certificate(ssl_ctx)) {
        return 0;
    }

    if (SSL_CTX_set_tlsext_use_srtp(ssl_ctx, "SRTP_AEAD_AES_256_GCM:SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")) {
        return 0;
    }

    if (!SSL_CTX_set_cipher_list(ssl_ctx, "HIGH:!aNULL:!MD5:!RC4")) {
        return 0;
    }

    if ((*ssl = SSL_new(ssl_ctx)) == NULL) {
        return 0;
    }

    if ((bio = BIO_new(udp_bio_method)) == NULL) {
        return 0;
    }

    SSL_set_mtu(*ssl, DTLS_MTU);
    SSL_set_bio(*ssl, bio, bio);
    SSL_set_options(*ssl, SSL_OP_NO_QUERY_MTU);

    return 1;
}

void run(SSL *ssl, struct sockaddr *dest_addr, int sockfd) {
    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    char buffer[BUFSIZE];
    int handshake_complete = 0;
    BIO_UDP_CTX *ctx = calloc(1, sizeof(*ctx));
    BIO_set_data(SSL_get_rbio(ssl), ctx);
    
    if (!ctx) {
        fprintf(stderr, "Failed to allocate BIO context\n");
        exit(EXIT_FAILURE);
    }

    ctx->sockfd = sockfd;
    ctx->peer_len = sizeof(*dest_addr);
    memcpy(&ctx->peer, dest_addr, ctx->peer_len);

    /* We need to wait for the first ClientHello to get the destination address */
    while (dest_addr->sa_family != AF_INET) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        char tmp[1500];

        // Peek or full read the first ClientHello
        ssize_t n = recvfrom(ctx->sockfd, tmp, sizeof(tmp), MSG_PEEK,
                            (struct sockaddr*)&client_addr, &client_len);
        if (n < 0) {
            // perror("recvfrom initial ClientHello");
            continue;
        }
        // Store it in your custom BIO state:
        memcpy(&ctx->peer, &client_addr, sizeof(client_addr));
        ctx->peer_len = client_len;
        break;
    }

    // Start the handshake process
    int ssl_ret = SSL_do_handshake(ssl);
    int ssl_error = SSL_get_error(ssl, ssl_ret);

    /* Handshake */
    int ret;
    while ((ret = SSL_do_handshake(ssl)) != 1) {
        int ssl_err = SSL_get_error(ssl, ret);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) continue;
        fprintf(stderr, "Handshake error: %d\n", ssl_err);

        fprintf(stderr,
        ">>> Handshake failed: return=%d, SSL_get_error=%d (%s)\n",
        ret, ssl_err,
        ssl_err == SSL_ERROR_SYSCALL ? "SSL_ERROR_SYSCALL" : "");

        // Print OpenSSL error queue
        ERR_print_errors_fp(stderr);

        // If it really was a syscall error, print errno
        if (ssl_err == SSL_ERROR_SYSCALL) {
            fprintf(stderr, "errno=%d (%s)\n", errno, strerror(errno));
        }
        exit(EXIT_FAILURE);
    }
    printf("Handshake Complete\n");

    SSL_shutdown(ssl);
    BIO_free_all(SSL_get_rbio(ssl));
}

#endif