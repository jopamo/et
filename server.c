#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <sys/socket.h>      // For socket(), bind(), listen(), accept()
#include <netinet/in.h>      // For sockaddr_in, INADDR_ANY
#include <arpa/inet.h>       // For htons()
#include <pthread.h>         // For multithreading

#define PORT 443
#define MAX_BUFFER_SIZE 4096  // Larger buffer size for better handling of bigger outputs

// Function to handle client requests
void handle_client(SSL *ssl) {
    char buffer[MAX_BUFFER_SIZE];
    int bytes;

    while (1) {
        // Read command from client
        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            break; // Error or client disconnected
        }
        buffer[bytes] = '\0'; // Null terminate the received command

        // Log the command (for audit/troubleshooting purposes)
        printf("Received command: %s\n", buffer);

        // Execute the command
        FILE *fp = popen(buffer, "r");
        if (fp == NULL) {
            SSL_write(ssl, "Error executing command\n", 24);
        } else {
            // Read command output and send it back to the client
            while (fgets(buffer, sizeof(buffer), fp) != NULL) {
                SSL_write(ssl, buffer, strlen(buffer));
            }
            fclose(fp);
        }
    }
}

// Function to handle each client in a new thread
void *client_handler(void *client_fd_ptr) {
    int client_fd = *((int *)client_fd_ptr);
    SSL_CTX *ctx = (SSL_CTX *)client_fd_ptr;  // Ensure to pass the ctx in a more proper way
    SSL *ssl = SSL_new(ctx);

    // SSL handshake
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_fd);
        SSL_free(ssl);
        pthread_exit(NULL);  // Close thread if SSL handshake fails
    }

    // Handle the client
    handle_client(ssl);

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);

    pthread_exit(NULL);
}

int main() {
    SSL_CTX *ctx;
    int server_fd;
    struct sockaddr_in server_addr;

    // Initialize SSL
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(1);
    }

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx)) {
        perror("Unable to load certificates");
        exit(1);
    }

    // Set up client certificate verification (authentication)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);  // Load CA certificate

    // Create server socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Unable to create socket");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }

    listen(server_fd, 1);

    // Accept client connections and handle them in separate threads
    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }

        // Create a new thread to handle the client
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, client_handler, (void *)&client_fd) != 0) {
            perror("Thread creation failed");
            close(client_fd);
            continue;
        }

        // Detach the thread so that resources are automatically cleaned up when done
        pthread_detach(thread_id);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
