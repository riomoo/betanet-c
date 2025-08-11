/*
* This is just a simple HTX program
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

// Simplified HTX structures
typedef struct {
    int sockfd;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    pthread_mutex_t mutex;
} htx_connection_t;

// Global flag for graceful shutdown
static volatile int running = 1;

// Signal handler
void signal_handler(int sig) {
    (void)sig;
    running = 0;
    printf("\nShutting down gracefully...\n");
}

// Initialize OpenSSL
int init_ssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    return 1;
}

void cleanup_ssl() {
    EVP_cleanup();
    ERR_free_strings();
}

// Generate a self-signed certificate for testing (OpenSSL 3.0 compatible)
int generate_test_certificate(SSL_CTX *ctx) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    X509 *x509 = NULL;

    // Generate RSA key pair using EVP interface
    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) {
        printf("[ERROR] Failed to create key context\n");
        return -1;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        printf("[ERROR] Failed to initialize key generation\n");
        EVP_PKEY_CTX_free(pkey_ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0) {
        printf("[ERROR] Failed to set key size\n");
        EVP_PKEY_CTX_free(pkey_ctx);
        return -1;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        printf("[ERROR] Failed to generate key pair\n");
        EVP_PKEY_CTX_free(pkey_ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pkey_ctx);

    // Create certificate
    x509 = X509_new();
    if (!x509) {
        printf("[ERROR] Failed to create certificate\n");
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Set certificate version (v3 = 2)
    X509_set_version(x509, 2);

    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year

    // Set public key
    X509_set_pubkey(x509, pkey);

    // Set subject and issuer names
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"HTX Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);

    X509_set_issuer_name(x509, name);

    // Self-sign the certificate
    if (X509_sign(x509, pkey, EVP_sha256()) == 0) {
        printf("[ERROR] Failed to sign certificate\n");
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Set certificate and key in SSL context
    if (SSL_CTX_use_certificate(ctx, x509) != 1) {
        printf("[ERROR] Failed to use certificate\n");
        ERR_print_errors_fp(stderr);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        printf("[ERROR] Failed to use private key\n");
        ERR_print_errors_fp(stderr);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Verify that the private key matches the certificate
    if (SSL_CTX_check_private_key(ctx) != 1) {
        printf("[ERROR] Private key does not match certificate\n");
        ERR_print_errors_fp(stderr);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    X509_free(x509);
    EVP_PKEY_free(pkey);

    printf("[SERVER] Generated self-signed certificate for testing\n");
    return 0;
}

// Simple client function (unchanged, but add better error handling)
int run_client(const char *host, int port) {
    printf("Starting simple HTX client (connecting to %s:%d)\n", host, port);

    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    // Create SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        close(sockfd);
        return -1;
    }

    // Disable certificate verification for testing
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, host);

    // Perform TLS handshake
    printf("[CLIENT] Starting TLS handshake...\n");
    int ssl_err = SSL_connect(ssl);
    if (ssl_err <= 0) {
        int error = SSL_get_error(ssl, ssl_err);
        printf("[ERROR] SSL_connect failed with error %d\n", error);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    printf("[CLIENT] TLS connection established (cipher: %s)\n", SSL_get_cipher(ssl));

    // Send simple HTTP request
    const char *request =
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: HTX-Test-Client/1.0\r\n"
        "Connection: close\r\n"
        "\r\n";

    int write_result = SSL_write(ssl, request, strlen(request));
    if (write_result <= 0) {
        int error = SSL_get_error(ssl, write_result);
        printf("[ERROR] SSL_write failed with error %d\n", error);
        ERR_print_errors_fp(stderr);
    } else {
        printf("[CLIENT] Sent HTTP request (%d bytes)\n", write_result);

        // Read response
        char response[4096];
        int bytes_read = SSL_read(ssl, response, sizeof(response) - 1);
        if (bytes_read > 0) {
            response[bytes_read] = '\0';
            printf("[CLIENT] Received response (%d bytes):\n%s\n", bytes_read, response);
        } else if (bytes_read <= 0) {
            int error = SSL_get_error(ssl, bytes_read);
            printf("[ERROR] SSL_read failed with error %d\n", error);
        }
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);

    printf("[CLIENT] Disconnected\n");
    return 0;
}

// Fixed server function with proper TLS handling
int run_server(int port) {
    printf("Starting simple HTX server on port %d\n", port);

    // Create listening socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        close(listen_fd);
        return -1;
    }

    // Create SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        close(listen_fd);
        return -1;
    }

    // Generate test certificate
    if (generate_test_certificate(ctx) != 0) {
        printf("[ERROR] Failed to generate test certificate\n");
        SSL_CTX_free(ctx);
        close(listen_fd);
        return -1;
    }

    printf("[SERVER] Listening for connections...\n");

    while (running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (running) {
                perror("accept");
            }
            continue;
        }

        printf("[SERVER] New client connected from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Create SSL connection for this client
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            printf("[ERROR] Failed to create SSL object\n");
            close(client_fd);
            continue;
        }

        SSL_set_fd(ssl, client_fd);

        // Perform TLS handshake
        printf("[SERVER] Starting TLS handshake...\n");
        int ssl_err = SSL_accept(ssl);
        if (ssl_err <= 0) {
            int error = SSL_get_error(ssl, ssl_err);
            printf("[ERROR] SSL_accept failed with error %d\n", error);
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        printf("[SERVER] TLS handshake completed (cipher: %s)\n", SSL_get_cipher(ssl));

        // Read client request
        char buffer[4096];
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            printf("[SERVER] Received request (%d bytes):\n%s\n", bytes_read, buffer);

            // Send HTTP response over TLS
            const char *response =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 55\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Hello from HTX server! TLS connection is working.\r\n";

            int write_result = SSL_write(ssl, response, strlen(response));
            if (write_result > 0) {
                printf("[SERVER] Sent HTTP response (%d bytes)\n", write_result);
            } else {
                int error = SSL_get_error(ssl, write_result);
                printf("[ERROR] SSL_write failed with error %d\n", error);
            }
        } else if (bytes_read <= 0) {
            int error = SSL_get_error(ssl, bytes_read);
            printf("[ERROR] SSL_read failed with error %d\n", error);
        }

        // Clean shutdown of SSL connection
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        printf("[SERVER] Client disconnected\n");
    }

    SSL_CTX_free(ctx);
    close(listen_fd);
    printf("[SERVER] Server stopped\n");
    return 0;
}

// Plain HTTP server mode (for comparison/testing)
int run_plain_server(int port) {
    printf("Starting plain HTTP server on port %d (no TLS)\n", port);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        close(listen_fd);
        return -1;
    }

    printf("[PLAIN] Listening for connections...\n");

    while (running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (running) {
                perror("accept");
            }
            continue;
        }

        printf("[PLAIN] New client connected from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        char buffer[4096];
        int bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            printf("[PLAIN] Received request:\n%s\n", buffer);

            const char *response =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 47\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Hello from plain HTTP server! No encryption.\r\n";

            send(client_fd, response, strlen(response), 0);
            printf("[PLAIN] Sent HTTP response\n");
        }

        close(client_fd);
        printf("[PLAIN] Client disconnected\n");
    }

    close(listen_fd);
    printf("[PLAIN] Plain server stopped\n");
    return 0;
}

// Performance test (updated for TLS)
int run_performance_test(const char *host, int port, int num_connections, int use_tls) {
    printf("Running performance test: %d connections (%s)\n",
           num_connections, use_tls ? "TLS" : "plain");

    clock_t start_time = clock();
    int successful = 0;

    for (int i = 0; i < num_connections; i++) {
        printf("[PERF] Connection %d/%d\r", i + 1, num_connections);
        fflush(stdout);

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) continue;

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        inet_pton(AF_INET, host, &server_addr.sin_addr);

        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            if (use_tls) {
                SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
                SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, sockfd);

                if (SSL_connect(ssl) > 0) {
                    const char *msg = "GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n";
                    if (SSL_write(ssl, msg, strlen(msg)) > 0) {
                        char response[1024];
                        SSL_read(ssl, response, sizeof(response));
                        successful++;
                    }
                }

                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
            } else {
                const char *msg = "GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n";
                if (send(sockfd, msg, strlen(msg), 0) > 0) {
                    char response[1024];
                    recv(sockfd, response, sizeof(response), 0);
                    successful++;
                }
            }
        }

        close(sockfd);
    }

    clock_t end_time = clock();
    double elapsed = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    printf("\n[PERF] Performance test completed\n");
    printf("[PERF] Successful connections: %d/%d\n", successful, num_connections);
    printf("[PERF] Total time: %.2f seconds\n", elapsed);
    printf("[PERF] Connections per second: %.2f\n", successful / elapsed);

    return 0;
}

// Self-test function (enhanced)
int run_self_test() {
    printf("Running HTX self-tests...\n");

    // Test 1: OpenSSL functionality
    printf("[TEST] Testing OpenSSL random number generation...\n");
    unsigned char random_bytes[32];
    if (RAND_bytes(random_bytes, 32) == 1) {
        printf("[PASS] Random number generation works\n");
    } else {
        printf("[FAIL] Random number generation failed\n");
        return -1;
    }

    // Test 2: Socket creation
    printf("[TEST] Testing socket creation...\n");
    int test_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (test_sock >= 0) {
        printf("[PASS] Socket creation works\n");
        close(test_sock);
    } else {
        printf("[FAIL] Socket creation failed\n");
        return -1;
    }

    // Test 3: SSL context creation
    printf("[TEST] Testing SSL context creation...\n");
    SSL_CTX *test_ctx = SSL_CTX_new(TLS_client_method());
    if (test_ctx) {
        printf("[PASS] SSL context creation works\n");
        SSL_CTX_free(test_ctx);
    } else {
        printf("[FAIL] SSL context creation failed\n");
        return -1;
    }

    // Test 4: Certificate generation
    printf("[TEST] Testing certificate generation...\n");
    SSL_CTX *cert_ctx = SSL_CTX_new(TLS_server_method());
    if (cert_ctx && generate_test_certificate(cert_ctx) == 0) {
        printf("[PASS] Certificate generation works\n");
        SSL_CTX_free(cert_ctx);
    } else {
        printf("[FAIL] Certificate generation failed\n");
        if (cert_ctx) SSL_CTX_free(cert_ctx);
        return -1;
    }

    printf("[PASS] All tests passed!\n");
    return 0;
}

// Main function
int main(int argc, char *argv[]) {
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize OpenSSL
    if (!init_ssl()) {
        printf("Failed to initialize OpenSSL\n");
        return 1;
    }

    // Parse command line arguments
    if (argc < 2) {
        printf("HTX Example Program (Fixed)\n");
        printf("Usage: %s <mode> [options]\n\n", argv[0]);
        printf("Modes:\n");
        printf("  client <host> <port>         - Connect to TLS server\n");
        printf("  server <port>                - Run TLS server\n");
        printf("  plain <port>                 - Run plain HTTP server\n");
        printf("  perf <host> <port> <num> [tls] - Performance test\n");
        printf("  test                         - Run self-tests\n");
        printf("\nExamples:\n");
        printf("  %s server 8443              # TLS server on port 8443\n", argv[0]);
        printf("  %s client localhost 8443    # Connect to TLS server\n", argv[0]);
        printf("  %s plain 8080               # Plain HTTP server\n", argv[0]);
        printf("  %s perf localhost 8443 10 tls # TLS performance test\n", argv[0]);
        printf("  %s test                     # Self-tests\n", argv[0]);
        cleanup_ssl();
        return 1;
    }

    const char *mode = argv[1];
    int result = 0;

    if (strcmp(mode, "client") == 0) {
        if (argc < 4) {
            printf("Usage: %s client <host> <port>\n", argv[0]);
            result = 1;
        } else {
            const char *host = argv[2];
            int port = atoi(argv[3]);
            result = run_client(host, port);
        }
    }
    else if (strcmp(mode, "server") == 0) {
        if (argc < 3) {
            printf("Usage: %s server <port>\n", argv[0]);
            result = 1;
        } else {
            int port = atoi(argv[2]);
            result = run_server(port);
        }
    }
    else if (strcmp(mode, "plain") == 0) {
        if (argc < 3) {
            printf("Usage: %s plain <port>\n", argv[0]);
            result = 1;
        } else {
            int port = atoi(argv[2]);
            result = run_plain_server(port);
        }
    }
    else if (strcmp(mode, "perf") == 0) {
        if (argc < 5) {
            printf("Usage: %s perf <host> <port> <connections> [tls]\n", argv[0]);
            result = 1;
        } else {
            const char *host = argv[2];
            int port = atoi(argv[3]);
            int connections = atoi(argv[4]);
            int use_tls = (argc > 5 && strcmp(argv[5], "tls") == 0);
            result = run_performance_test(host, port, connections, use_tls);
        }
    }
    else if (strcmp(mode, "test") == 0) {
        result = run_self_test();
    }
    else {
        printf("Unknown mode: %s\n", mode);
        result = 1;
    }

    // Cleanup
    cleanup_ssl();
    return result;
}
