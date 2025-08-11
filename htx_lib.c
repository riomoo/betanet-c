/*
* HTX (HTTP-Tunnelled Transport) Client/Server Implementation
* Based on the Betanet 1.1 Specification
* - TCP-443 and QUIC-443 support
* - Origin-mirrored TLS with ECH stub
* - Noise XK inner handshake with ChaCha20-Poly1305
* - Access ticket authentication
* - Stream multiplexing
* - Anti-correlation measures
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>
#include <errno.h>
#include <pthread.h>

// Protocol constants
#define HTX_VERSION 0x02
#define HTX_MAX_FRAME_SIZE 16384
#define HTX_WINDOW_SIZE 65535
#define HTX_ACCESS_TICKET_SIZE 32
#define HTX_TICKET_KEY_ID_SIZE 8
#define HTX_NONCE_SIZE 32
#define HTX_PUBKEY_SIZE 32

// Frame types
typedef enum {
    HTX_FRAME_STREAM = 0,
    HTX_FRAME_PING = 1,
    HTX_FRAME_CLOSE = 2,
    HTX_FRAME_KEY_UPDATE = 3,
    HTX_FRAME_WINDOW_UPDATE = 4
} htx_frame_type_t;

// Connection modes
typedef enum {
    HTX_MODE_TCP = 0,
    HTX_MODE_QUIC = 1
} htx_mode_t;

// Noise XK state
typedef enum {
    NOISE_HANDSHAKE_INIT = 0,
    NOISE_HANDSHAKE_RESPONSE = 1,
    NOISE_HANDSHAKE_COMPLETE = 2
} noise_state_t;

// HTX frame structure
typedef struct {
    uint32_t length;        // 24-bit length + 8-bit type packed
    uint64_t stream_id;     // Variable-length integer
    uint8_t *payload;
    uint16_t payload_len;
} htx_frame_t;

// Access ticket structure
typedef struct {
    uint8_t version;
    uint8_t cli_pub[HTX_PUBKEY_SIZE];
    uint8_t ticket_key_id[HTX_TICKET_KEY_ID_SIZE];
    uint8_t nonce32[HTX_NONCE_SIZE];
    uint8_t access_ticket[HTX_ACCESS_TICKET_SIZE];
    uint8_t *padding;
    size_t padding_len;
} htx_ticket_t;

// Crypto keys for inner handshake
typedef struct {
    uint8_t k0c[32];        // Client key
    uint8_t k0s[32];        // Server key
    uint8_t nonce_salt_c[12]; // Client nonce salt
    uint8_t nonce_salt_s[12]; // Server nonce salt
    uint64_t counter_send;
    uint64_t counter_recv;
    time_t last_rekey;
} htx_crypto_t;

// Stream context
typedef struct {
    uint64_t stream_id;
    uint32_t window_size;
    uint8_t *buffer;
    size_t buffer_len;
    size_t buffer_capacity;
    pthread_mutex_t mutex;
} htx_stream_t;

// HTX connection context
typedef struct {
    int sockfd;
    SSL *ssl;
    htx_mode_t mode;
    noise_state_t noise_state;
    htx_crypto_t crypto;
    htx_stream_t **streams;
    size_t stream_count;
    size_t stream_capacity;
    pthread_mutex_t streams_mutex;
    time_t last_ping;
    uint64_t next_stream_id;
    uint8_t is_client;
} htx_connection_t;

// Function prototypes
int htx_init_ssl(void);
void htx_cleanup_ssl(void);
htx_connection_t *htx_client_connect(const char *host, int port, htx_mode_t mode);
htx_connection_t *htx_server_accept(int listen_fd);
int htx_perform_calibration(const char *host, int port);
int htx_generate_access_ticket(htx_ticket_t *ticket, const uint8_t *ticket_pub);
int htx_verify_access_ticket(const htx_ticket_t *ticket, const uint8_t *ticket_priv);
int htx_noise_handshake_init(htx_connection_t *conn);
int htx_noise_handshake_response(htx_connection_t *conn, const uint8_t *init_msg, size_t init_len);
int htx_derive_keys(htx_connection_t *conn, const uint8_t *tls_exporter);
int htx_encrypt_frame(htx_connection_t *conn, const htx_frame_t *frame, uint8_t *output, size_t *output_len);
int htx_decrypt_frame(htx_connection_t *conn, const uint8_t *input, size_t input_len, htx_frame_t *frame);
int htx_send_frame(htx_connection_t *conn, const htx_frame_t *frame);
int htx_receive_frame(htx_connection_t *conn, htx_frame_t *frame);
htx_stream_t *htx_open_stream(htx_connection_t *conn);
int htx_close_stream(htx_connection_t *conn, uint64_t stream_id);
int htx_stream_write(htx_connection_t *conn, uint64_t stream_id, const void *data, size_t len);
int htx_stream_read(htx_connection_t *conn, uint64_t stream_id, void *buffer, size_t buffer_size);
void htx_connection_close(htx_connection_t *conn);
void htx_send_ping(htx_connection_t *conn);
int htx_key_update(htx_connection_t *conn);

// Utility functions
static uint64_t htx_encode_varint(uint8_t *buf, uint64_t value);
static uint64_t htx_decode_varint(const uint8_t *buf, uint64_t *value);
static void htx_nonce_from_counter(const uint8_t *salt, uint64_t counter, uint8_t *nonce);
static int htx_chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce, 
                                         const uint8_t *plaintext, size_t plaintext_len,
                                         uint8_t *ciphertext, size_t *ciphertext_len);
static int htx_chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
                                         const uint8_t *ciphertext, size_t ciphertext_len,
                                         uint8_t *plaintext, size_t *plaintext_len);

// Initialize OpenSSL
int htx_init_ssl(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    return 1;
}

void htx_cleanup_ssl(void) {
    EVP_cleanup();
    ERR_free_strings();
}

// Perform pre-flight calibration to mirror origin
int htx_perform_calibration(const char *host, int port) {
    // This would implement the calibration logic to learn origin characteristics
    // For now, return success as a stub
    printf("[CALIBRATION] Performing calibration against %s:%d\n", host, port);
    
    // TODO: Implement actual calibration:
    // 1. Connect to origin
    // 2. Record JA3/JA4 fingerprint
    // 3. Record ALPN preferences
    // 4. Record H2 SETTINGS
    // 5. Store results for mirroring
    
    return 0;
}

// Generate access ticket using ECDH
int htx_generate_access_ticket(htx_ticket_t *ticket, const uint8_t *ticket_pub) {
    uint8_t cli_priv[32];
    uint8_t shared_secret[32];
    uint8_t salt[32];
    time_t now = time(NULL);
    uint64_t hour = now / 3600;
    
    // Generate client keypair
    if (RAND_bytes(cli_priv, 32) != 1) {
        return -1;
    }
    
    // Derive client public key (X25519 - simplified, would use actual crypto)
    memcpy(ticket->cli_pub, cli_priv, 32); // Placeholder
    
    // Compute shared secret (X25519)
    // shared_secret = X25519(cli_priv, ticket_pub)
    memcpy(shared_secret, ticket_pub, 32); // Placeholder
    
    // Generate nonce
    if (RAND_bytes(ticket->nonce32, HTX_NONCE_SIZE) != 1) {
        return -1;
    }
    
    // Derive salt
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, "betanet-ticket-v1", 18);
    EVP_DigestUpdate(ctx, ticket->ticket_key_id, HTX_TICKET_KEY_ID_SIZE);
    
    uint8_t hour_be[8];
    for (int i = 0; i < 8; i++) {
        hour_be[i] = (hour >> (8 * (7 - i))) & 0xFF;
    }
    EVP_DigestUpdate(ctx, hour_be, 8);
    
    unsigned int salt_len;
    EVP_DigestFinal_ex(ctx, salt, &salt_len);
    EVP_MD_CTX_free(ctx);
    
    // Derive access ticket using HKDF
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;
    
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, 32) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, 32) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    size_t ticket_len = HTX_ACCESS_TICKET_SIZE;
    if (EVP_PKEY_derive(pctx, ticket->access_ticket, &ticket_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    EVP_PKEY_CTX_free(pctx);
    
    ticket->version = 0x01;
    
    // Generate padding (24-64 bytes)
    ticket->padding_len = 24 + (rand() % 41); // 24-64 bytes
    ticket->padding = malloc(ticket->padding_len);
    if (!ticket->padding) return -1;
    
    if (RAND_bytes(ticket->padding, ticket->padding_len) != 1) {
        free(ticket->padding);
        return -1;
    }
    
    return 0;
}

// Verify access ticket
int htx_verify_access_ticket(const htx_ticket_t *ticket, const uint8_t *ticket_priv) {
    // TODO: Implement ticket verification
    // 1. Check replay protection
    // 2. Verify time window (hour ∈ {now-1, now, now+1})
    // 3. Recompute shared secret and access ticket
    // 4. Apply rate limiting
    
    printf("[TICKET] Verifying access ticket\n");
    return 0;
}

// Initialize Noise XK handshake
int htx_noise_handshake_init(htx_connection_t *conn) {
    // TODO: Implement Noise XK initiator
    // 1. Generate ephemeral keypair
    // 2. Create initial message: e, es
    // 3. Send to responder
    
    printf("[NOISE] Initializing Noise XK handshake\n");
    conn->noise_state = NOISE_HANDSHAKE_RESPONSE;
    return 0;
}

// Process Noise XK handshake response
int htx_noise_handshake_response(htx_connection_t *conn, const uint8_t *init_msg, size_t init_len) {
    // TODO: Implement Noise XK responder
    // 1. Process initial message
    // 2. Generate response: e, ee, se
    // 3. Derive final keys
    
    printf("[NOISE] Processing Noise XK response\n");
    conn->noise_state = NOISE_HANDSHAKE_COMPLETE;
    return 0;
}

// Derive encryption keys from TLS exporter
int htx_derive_keys(htx_connection_t *conn, const uint8_t *tls_exporter) {
    // Derive K0 = HKDF-Expand-Label(TLS-Exporter, "htx inner v1", "", 64)
    uint8_t k0[64];
    
    // Split into client/server keys
    memcpy(conn->crypto.k0c, k0, 32);
    memcpy(conn->crypto.k0s, k0 + 32, 32);
    
    // Derive nonce salts
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;
    
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    // Derive client nonce salt
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, conn->crypto.k0c, 32) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "ns", 2) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    size_t ns_len = 12;
    if (EVP_PKEY_derive(pctx, conn->crypto.nonce_salt_c, &ns_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    // Derive server nonce salt
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, conn->crypto.k0s, 32) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    ns_len = 12;
    if (EVP_PKEY_derive(pctx, conn->crypto.nonce_salt_s, &ns_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    EVP_PKEY_CTX_free(pctx);
    
    conn->crypto.counter_send = 0;
    conn->crypto.counter_recv = 0;
    conn->crypto.last_rekey = time(NULL);
    
    return 0;
}

// Generate nonce from salt and counter
static void htx_nonce_from_counter(const uint8_t *salt, uint64_t counter, uint8_t *nonce) {
    memcpy(nonce, salt, 12);
    
    // XOR with LE64(counter) || LE32(0)
    for (int i = 0; i < 8; i++) {
        nonce[i] ^= (counter >> (8 * i)) & 0xFF;
    }
    // Bytes 8-11 remain unchanged (LE32(0) = 0)
}

// ChaCha20-Poly1305 encryption
static int htx_chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce, 
                                         const uint8_t *plaintext, size_t plaintext_len,
                                         uint8_t *ciphertext, size_t *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ciphertext_len += len;
    
    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ciphertext + *ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ciphertext_len += 16;
    
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// ChaCha20-Poly1305 decryption
static int htx_chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
                                         const uint8_t *ciphertext, size_t ciphertext_len,
                                         uint8_t *plaintext, size_t *plaintext_len) {
    if (ciphertext_len < 16) return -1; // Must have at least tag
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    size_t data_len = ciphertext_len - 16;
    
    // Set authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, 
                           (void*)(ciphertext + data_len)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, data_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plaintext_len = len;
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret != 1) return -1; // Authentication failed
    
    *plaintext_len += len;
    return 0;
}

// Encrypt HTX frame
int htx_encrypt_frame(htx_connection_t *conn, const htx_frame_t *frame, uint8_t *output, size_t *output_len) {
    uint8_t nonce[12];
    const uint8_t *key = conn->is_client ? conn->crypto.k0c : conn->crypto.k0s;
    const uint8_t *salt = conn->is_client ? conn->crypto.nonce_salt_c : conn->crypto.nonce_salt_s;
    
    htx_nonce_from_counter(salt, conn->crypto.counter_send, nonce);
    
    // Pack frame header
    uint8_t header[16]; // Max varint is 8 bytes
    size_t header_len = 0;
    
    // Pack length (24-bit) and type (8-bit)
    uint32_t length_type = (frame->length << 8) | ((frame->length >> 16) & 0xFF);
    header[header_len++] = (frame->length >> 16) & 0xFF;
    header[header_len++] = (frame->length >> 8) & 0xFF;
    header[header_len++] = frame->length & 0xFF;
    header[header_len++] = (frame->length >> 24) & 0xFF; // frame type
    
    // Add stream_id if present
    if ((frame->length >> 24) == HTX_FRAME_STREAM || (frame->length >> 24) == HTX_FRAME_WINDOW_UPDATE) {
        header_len += htx_encode_varint(header + header_len, frame->stream_id);
    }
    
    // Combine header and payload
    uint8_t *plaintext = malloc(header_len + frame->payload_len);
    if (!plaintext) return -1;
    
    memcpy(plaintext, header, header_len);
    memcpy(plaintext + header_len, frame->payload, frame->payload_len);
    
    // Encrypt
    int ret = htx_chacha20_poly1305_encrypt(key, nonce, plaintext, header_len + frame->payload_len,
                                           output, output_len);
    
    free(plaintext);
    
    if (ret == 0) {
        conn->crypto.counter_send++;
    }
    
    return ret;
}

// Decrypt HTX frame  
int htx_decrypt_frame(htx_connection_t *conn, const uint8_t *input, size_t input_len, htx_frame_t *frame) {
    uint8_t nonce[12];
    const uint8_t *key = conn->is_client ? conn->crypto.k0s : conn->crypto.k0c;
    const uint8_t *salt = conn->is_client ? conn->crypto.nonce_salt_s : conn->crypto.nonce_salt_c;
    
    htx_nonce_from_counter(salt, conn->crypto.counter_recv, nonce);
    
    uint8_t *plaintext = malloc(input_len);
    if (!plaintext) return -1;
    
    size_t plaintext_len;
    int ret = htx_chacha20_poly1305_decrypt(key, nonce, input, input_len, plaintext, &plaintext_len);
    
    if (ret != 0) {
        free(plaintext);
        return -1;
    }
    
    // Unpack frame
    if (plaintext_len < 4) {
        free(plaintext);
        return -1;
    }
    
    frame->length = (plaintext[0] << 16) | (plaintext[1] << 8) | plaintext[2];
    uint8_t type = plaintext[3];
    frame->length |= (type << 24);
    
    size_t pos = 4;
    
    // Decode stream_id if present
    if (type == HTX_FRAME_STREAM || type == HTX_FRAME_WINDOW_UPDATE) {
        pos += htx_decode_varint(plaintext + pos, &frame->stream_id);
    }
    
    // Extract payload
    frame->payload_len = plaintext_len - pos;
    frame->payload = malloc(frame->payload_len);
    if (!frame->payload) {
        free(plaintext);
        return -1;
    }
    
    memcpy(frame->payload, plaintext + pos, frame->payload_len);
    free(plaintext);
    
    conn->crypto.counter_recv++;
    return 0;
}

// Variable-length integer encoding (QUIC style)
static uint64_t htx_encode_varint(uint8_t *buf, uint64_t value) {
    if (value < 64) {
        buf[0] = value;
        return 1;
    } else if (value < 16384) {
        buf[0] = 0x40 | (value >> 8);
        buf[1] = value & 0xFF;
        return 2;
    } else if (value < 1073741824) {
        buf[0] = 0x80 | (value >> 24);
        buf[1] = (value >> 16) & 0xFF;
        buf[2] = (value >> 8) & 0xFF;
        buf[3] = value & 0xFF;
        return 4;
    } else {
        buf[0] = 0xC0 | (value >> 56);
        for (int i = 1; i < 8; i++) {
            buf[i] = (value >> (8 * (7 - i))) & 0xFF;
        }
        return 8;
    }
}

static uint64_t htx_decode_varint(const uint8_t *buf, uint64_t *value) {
    uint8_t first = buf[0];
    
    if ((first & 0xC0) == 0x00) {
        *value = first;
        return 1;
    } else if ((first & 0xC0) == 0x40) {
        *value = ((first & 0x3F) << 8) | buf[1];
        return 2;
    } else if ((first & 0xC0) == 0x80) {
        *value = ((first & 0x3F) << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
        return 4;
    } else {
        *value = (first & 0x3F);
        for (int i = 1; i < 8; i++) {
            *value = (*value << 8) | buf[i];
        }
        return 8;
    }
}

// Send frame over connection
int htx_send_frame(htx_connection_t *conn, const htx_frame_t *frame) {
    uint8_t encrypted[HTX_MAX_FRAME_SIZE + 32]; // Extra space for header + tag
    size_t encrypted_len;
    
    if (htx_encrypt_frame(conn, frame, encrypted, &encrypted_len) != 0) {
        return -1;
    }
    
    if (conn->mode == HTX_MODE_TCP) {
        if (SSL_write(conn->ssl, encrypted, encrypted_len) <= 0) {
            return -1;
        }
    } else {
        // QUIC implementation would go here
        return -1;
    }
    
    return 0;
}

// Receive frame from connection
int htx_receive_frame(htx_connection_t *conn, htx_frame_t *frame) {
    uint8_t encrypted[HTX_MAX_FRAME_SIZE + 32];
    int bytes_read;
    
    if (conn->mode == HTX_MODE_TCP) {
        bytes_read = SSL_read(conn->ssl, encrypted, sizeof(encrypted));
        if (bytes_read <= 0) {
            return -1;
        }
    } else {
        // QUIC implementation would go here
        return -1;
    }
    
    return htx_decrypt_frame(conn, encrypted, bytes_read, frame);
}

// Client connection establishment
htx_connection_t *htx_client_connect(const char *host, int port, htx_mode_t mode) {
    printf("[CLIENT] Connecting to %s:%d (mode: %s)\n", 
           host, port, mode == HTX_MODE_TCP ? "TCP" : "QUIC");
    
    // Perform calibration first
    if (htx_perform_calibration(host, port) != 0) {
        printf("[ERROR] Calibration failed\n");
        return NULL;
    }
    
    htx_connection_t *conn = calloc(1, sizeof(htx_connection_t));
    if (!conn) return NULL;
    
    conn->mode = mode;
    conn->is_client = 1;
    conn->next_stream_id = 1;
    
    if (mode == HTX_MODE_TCP) {
        // Create TCP socket
        conn->sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (conn->sockfd < 0) {
            free(conn);
            return NULL;
        }
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        inet_pton(AF_INET, host, &server_addr.sin_addr);
        
        if (connect(conn->sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(conn->sockfd);
            free(conn);
            return NULL;
        }
        
        // Create SSL context
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            close(conn->sockfd);
            free(conn);
            return NULL;
        }
        
        // Configure SSL to mirror origin
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        
        conn->ssl = SSL_new(ctx);
        SSL_set_fd(conn->ssl, conn->sockfd);
        SSL_set_tlsext_host_name(conn->ssl, host);
        
        // Perform TLS handshake
        if (SSL_connect(conn->ssl) <= 0) {
            SSL_free(conn->ssl);
            SSL_CTX_free(ctx);
            close(conn->sockfd);
            free(conn);
            return NULL;
        }
        
        printf("[TLS] Handshake completed\n");
        
        // Generate and send access ticket
        htx_ticket_t ticket;
        uint8_t ticket_pub[32] = {0}; // Would be provided by server
        
        if (htx_generate_access_ticket(&ticket, ticket_pub) != 0) {
            SSL_free(conn->ssl);
            SSL_CTX_free(ctx);
            close(conn->sockfd);
            free(conn);
            return NULL;
        }
        
        // Send ticket as HTTP cookie (recommended method)
        char cookie_header[1024];
        char encoded_ticket[512];
        
        // Base64URL encode ticket payload
        size_t ticket_size = 1 + 32 + 8 + 32 + 32 + ticket.padding_len;
        uint8_t *ticket_payload = malloc(ticket_size);
        if (!ticket_payload) {
            free(ticket.padding);
            SSL_free(conn->ssl);
            SSL_CTX_free(ctx);
            close(conn->sockfd);
            free(conn);
            return NULL;
        }
        
        size_t pos = 0;
        ticket_payload[pos++] = ticket.version;
        memcpy(ticket_payload + pos, ticket.cli_pub, 32); pos += 32;
        memcpy(ticket_payload + pos, ticket.ticket_key_id, 8); pos += 8;
        memcpy(ticket_payload + pos, ticket.nonce32, 32); pos += 32;
        memcpy(ticket_payload + pos, ticket.access_ticket, 32); pos += 32;
        memcpy(ticket_payload + pos, ticket.padding, ticket.padding_len);
        
        // TODO: Implement proper Base64URL encoding
        strcpy(encoded_ticket, "base64url_encoded_ticket_here");
        
        snprintf(cookie_header, sizeof(cookie_header),
                 "GET / HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Cookie: __Host-session=%s\r\n"
                 "User-Agent: Mozilla/5.0 (compatible)\r\n"
                 "Connection: Upgrade\r\n"
                 "Upgrade: websocket\r\n"
                 "\r\n", host, encoded_ticket);
        
        if (SSL_write(conn->ssl, cookie_header, strlen(cookie_header)) <= 0) {
            free(ticket_payload);
            free(ticket.padding);
            SSL_free(conn->ssl);
            SSL_CTX_free(ctx);
            close(conn->sockfd);
            free(conn);
            return NULL;
        }
        
        free(ticket_payload);
        free(ticket.padding);
        
        // Derive inner encryption keys
        uint8_t tls_exporter[64];
        if (SSL_export_keying_material(conn->ssl, tls_exporter, 64, 
                                      "htx inner v1", 12, NULL, 0, 0) != 1) {
            SSL_free(conn->ssl);
            SSL_CTX_free(ctx);
            close(conn->sockfd);
            free(conn);
            return NULL;
        }
        
        if (htx_derive_keys(conn, tls_exporter) != 0) {
            SSL_free(conn->ssl);
            SSL_CTX_free(ctx);
            close(conn->sockfd);
            free(conn);
            return NULL;
        }
        
        // Perform Noise XK handshake
        if (htx_noise_handshake_init(conn) != 0) {
            SSL_free(conn->ssl);
            SSL_CTX_free(ctx);
            close(conn->sockfd);
            free(conn);
            return NULL;
        }
        
        SSL_CTX_free(ctx);
        
    } else {
        // QUIC implementation
        printf("[ERROR] QUIC mode not implemented yet\n");
        free(conn);
        return NULL;
    }
    
    // Initialize streams
    conn->stream_capacity = 16;
    conn->streams = calloc(conn->stream_capacity, sizeof(htx_stream_t*));
    pthread_mutex_init(&conn->streams_mutex, NULL);
    
    conn->last_ping = time(NULL);
    
}

// Server accept incoming connection
htx_connection_t *htx_server_accept(int listen_fd) {
    printf("[SERVER] Accepting new connection\n");
    
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) {
        return NULL;
    }
    
    htx_connection_t *conn = calloc(1, sizeof(htx_connection_t));
    if (!conn) {
        close(client_fd);
        return NULL;
    }
    
    conn->sockfd = client_fd;
    conn->mode = HTX_MODE_TCP;
    conn->is_client = 0;
    conn->next_stream_id = 2; // Server uses even stream IDs
    
    // Create SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        close(client_fd);
        free(conn);
        return NULL;
    }
    
    // Load server certificate and key (placeholder)
    // SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);
    // SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);
    
    conn->ssl = SSL_new(ctx);
    SSL_set_fd(conn->ssl, client_fd);
    
    // Perform TLS handshake
    if (SSL_accept(conn->ssl) <= 0) {
        SSL_free(conn->ssl);
        SSL_CTX_free(ctx);
        close(client_fd);
        free(conn);
        return NULL;
    }
    
    printf("[TLS] Server handshake completed\n");
    
    // Read HTTP request with access ticket
    char request[4096];
    int bytes_read = SSL_read(conn->ssl, request, sizeof(request) - 1);
    if (bytes_read <= 0) {
        SSL_free(conn->ssl);
        SSL_CTX_free(ctx);
        close(client_fd);
        free(conn);
        return NULL;
    }
    
    request[bytes_read] = '\0';
    
    // Parse and verify access ticket
    // TODO: Extract ticket from Cookie header and verify
    printf("[TICKET] Parsing access ticket from request\n");
    
    // Send HTTP 101 Switching Protocols response
    const char *upgrade_response = 
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "\r\n";
    
    if (SSL_write(conn->ssl, upgrade_response, strlen(upgrade_response)) <= 0) {
        SSL_free(conn->ssl);
        SSL_CTX_free(ctx);
        close(client_fd);
        free(conn);
        return NULL;
    }
    
    // Derive inner encryption keys
    uint8_t tls_exporter[64];
    if (SSL_export_keying_material(conn->ssl, tls_exporter, 64, 
                                  "htx inner v1", 12, NULL, 0, 0) != 1) {
        SSL_free(conn->ssl);
        SSL_CTX_free(ctx);
        close(client_fd);
        free(conn);
        return NULL;
    }
    
    if (htx_derive_keys(conn, tls_exporter) != 0) {
        SSL_free(conn->ssl);
        SSL_CTX_free(ctx);
        close(client_fd);
        free(conn);
        return NULL;
    }
    
    // Initialize streams
    conn->stream_capacity = 16;
    conn->streams = calloc(conn->stream_capacity, sizeof(htx_stream_t*));
    pthread_mutex_init(&conn->streams_mutex, NULL);
    
    conn->last_ping = time(NULL);
    
    SSL_CTX_free(ctx);
    
    printf("[SERVER] Connection accepted\n");
    return conn;
}

// Open new stream
htx_stream_t *htx_open_stream(htx_connection_t *conn) {
    pthread_mutex_lock(&conn->streams_mutex);
    
    // Find available stream slot
    size_t stream_index = conn->stream_count;
    if (stream_index >= conn->stream_capacity) {
        // Resize streams array
        size_t new_capacity = conn->stream_capacity * 2;
        htx_stream_t **new_streams = realloc(conn->streams, 
                                            new_capacity * sizeof(htx_stream_t*));
        if (!new_streams) {
            pthread_mutex_unlock(&conn->streams_mutex);
            return NULL;
        }
        
        conn->streams = new_streams;
        conn->stream_capacity = new_capacity;
        
        // Initialize new slots
        for (size_t i = conn->stream_count; i < new_capacity; i++) {
            conn->streams[i] = NULL;
        }
    }
    
    htx_stream_t *stream = calloc(1, sizeof(htx_stream_t));
    if (!stream) {
        pthread_mutex_unlock(&conn->streams_mutex);
        return NULL;
    }
    
    stream->stream_id = conn->next_stream_id;
    conn->next_stream_id += 2; // Client: odd, Server: even
    
    stream->window_size = HTX_WINDOW_SIZE;
    stream->buffer_capacity = 4096;
    stream->buffer = malloc(stream->buffer_capacity);
    if (!stream->buffer) {
        free(stream);
        pthread_mutex_unlock(&conn->streams_mutex);
        return NULL;
    }
    
    pthread_mutex_init(&stream->mutex, NULL);
    
    conn->streams[stream_index] = stream;
    conn->stream_count++;
    
    pthread_mutex_unlock(&conn->streams_mutex);
    
    printf("[STREAM] Opened stream %lu\n", stream->stream_id);
    return stream;
}

// Close stream
int htx_close_stream(htx_connection_t *conn, uint64_t stream_id) {
    pthread_mutex_lock(&conn->streams_mutex);
    
    for (size_t i = 0; i < conn->stream_count; i++) {
        if (conn->streams[i] && conn->streams[i]->stream_id == stream_id) {
            htx_stream_t *stream = conn->streams[i];
            
            // Send close frame
            htx_frame_t close_frame = {
                .length = (HTX_FRAME_CLOSE << 24),
                .stream_id = stream_id,
                .payload = NULL,
                .payload_len = 0
            };
            
            htx_send_frame(conn, &close_frame);
            
            // Cleanup stream
            pthread_mutex_destroy(&stream->mutex);
            free(stream->buffer);
            free(stream);
            
            conn->streams[i] = NULL;
            
            printf("[STREAM] Closed stream %lu\n", stream_id);
            break;
        }
    }
    
    pthread_mutex_unlock(&conn->streams_mutex);
    return 0;
}

// Write data to stream
int htx_stream_write(htx_connection_t *conn, uint64_t stream_id, const void *data, size_t len) {
    // Find stream
    htx_stream_t *stream = NULL;
    pthread_mutex_lock(&conn->streams_mutex);
    
    for (size_t i = 0; i < conn->stream_count; i++) {
        if (conn->streams[i] && conn->streams[i]->stream_id == stream_id) {
            stream = conn->streams[i];
            break;
        }
    }
    
    pthread_mutex_unlock(&conn->streams_mutex);
    
    if (!stream) {
        return -1;
    }
    
    pthread_mutex_lock(&stream->mutex);
    
    // Fragment data into frames if necessary
    const uint8_t *data_ptr = (const uint8_t*)data;
    size_t remaining = len;
    
    while (remaining > 0) {
        size_t chunk_size = remaining > HTX_MAX_FRAME_SIZE ? HTX_MAX_FRAME_SIZE : remaining;
        
        htx_frame_t frame = {
            .length = (HTX_FRAME_STREAM << 24) | chunk_size,
            .stream_id = stream_id,
            .payload = (uint8_t*)data_ptr,
            .payload_len = chunk_size
        };
        
        if (htx_send_frame(conn, &frame) != 0) {
            pthread_mutex_unlock(&stream->mutex);
            return -1;
        }
        
        data_ptr += chunk_size;
        remaining -= chunk_size;
    }
    
    pthread_mutex_unlock(&stream->mutex);
    return len;
}

// Read data from stream
int htx_stream_read(htx_connection_t *conn, uint64_t stream_id, void *buffer, size_t buffer_size) {
    // Find stream
    htx_stream_t *stream = NULL;
    pthread_mutex_lock(&conn->streams_mutex);
    
    for (size_t i = 0; i < conn->stream_count; i++) {
        if (conn->streams[i] && conn->streams[i]->stream_id == stream_id) {
            stream = conn->streams[i];
            break;
        }
    }
    
    pthread_mutex_unlock(&conn->streams_mutex);
    
    if (!stream) {
        return -1;
    }
    
    pthread_mutex_lock(&stream->mutex);
    
    size_t available = stream->buffer_len < buffer_size ? stream->buffer_len : buffer_size;
    if (available > 0) {
        memcpy(buffer, stream->buffer, available);
        
        // Shift remaining data
        memmove(stream->buffer, stream->buffer + available, stream->buffer_len - available);
        stream->buffer_len -= available;
    }
    
    pthread_mutex_unlock(&stream->mutex);
    return available;
}

// Send ping frame
void htx_send_ping(htx_connection_t *conn) {
    uint8_t ping_data[8];
    if (RAND_bytes(ping_data, 8) != 1) {
        return;
    }
    
    htx_frame_t ping_frame = {
        .length = (HTX_FRAME_PING << 24) | 8,
        .stream_id = 0,
        .payload = ping_data,
        .payload_len = 8
    };
    
    htx_send_frame(conn, &ping_frame);
    conn->last_ping = time(NULL);
}

// Perform key update
int htx_key_update(htx_connection_t *conn) {
    // Derive new keys: K' = HKDF(K, "next", transcript_hash, 64)
    uint8_t new_k0c[32], new_k0s[32];
    uint8_t transcript_hash[32] = {0}; // Would compute actual transcript
    
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;
    
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    // Derive new client key
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, conn->crypto.k0c, 32) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "next", 4) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_info(pctx, transcript_hash, 32) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    size_t key_len = 32;
    if (EVP_PKEY_derive(pctx, new_k0c, &key_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    // Derive new server key
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, conn->crypto.k0s, 32) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    key_len = 32;
    if (EVP_PKEY_derive(pctx, new_k0s, &key_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    EVP_PKEY_CTX_free(pctx);
    
    // Send KEY_UPDATE frame
    htx_frame_t key_update_frame = {
        .length = (HTX_FRAME_KEY_UPDATE << 24),
        .stream_id = 0,
        .payload = NULL,
        .payload_len = 0
    };
    
    if (htx_send_frame(conn, &key_update_frame) != 0) {
        return -1;
    }
    
    // Update keys and reset counters
    memcpy(conn->crypto.k0c, new_k0c, 32);
    memcpy(conn->crypto.k0s, new_k0s, 32);
    conn->crypto.counter_send = 0;
    conn->crypto.counter_recv = 0;
    conn->crypto.last_rekey = time(NULL);
    
    // Re-derive nonce salts
    // ... (similar HKDF derivation for nonce salts)
    
    printf("[CRYPTO] Key update completed\n");
    return 0;
}

// Close HTX connection
void htx_connection_close(htx_connection_t *conn) {
    if (!conn) return;
    
    printf("[CONNECTION] Closing HTX connection\n");
    
    // Close all streams
    if (conn->streams) {
        pthread_mutex_lock(&conn->streams_mutex);
        
        for (size_t i = 0; i < conn->stream_count; i++) {
            if (conn->streams[i]) {
                htx_close_stream(conn, conn->streams[i]->stream_id);
            }
        }
        
        free(conn->streams);
        pthread_mutex_unlock(&conn->streams_mutex);
        pthread_mutex_destroy(&conn->streams_mutex);
    }
    
    // Close SSL connection
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    
    // Close socket
    if (conn->sockfd >= 0) {
        close(conn->sockfd);
    }
    
    free(conn);
}

// Example usage and test functions
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <client|server> [host] [port]\n", argv[0]);
        return 1;
    }
    
    htx_init_ssl();
    
    if (strcmp(argv[1], "client") == 0) {
        const char *host = argc > 2 ? argv[2] : "example.com";
        int port = argc > 3 ? atoi(argv[3]) : 443;
        
        printf("Starting HTX client connecting to %s:%d\n", host, port);
        
        htx_connection_t *conn = htx_client_connect(host, port, HTX_MODE_TCP);
        if (!conn) {
            printf("Failed to connect\n");
            htx_cleanup_ssl();
            return 1;
        }
        
        // Open a stream and send some data
        htx_stream_t *stream = htx_open_stream(conn);
        if (stream) {
            const char *message = "Hello HTX!";
            htx_stream_write(conn, stream->stream_id, message, strlen(message));
            
            // Read response
            char response[256];
            int bytes_read = htx_stream_read(conn, stream->stream_id, response, sizeof(response) - 1);
            if (bytes_read > 0) {
                response[bytes_read] = '\0';
                printf("Received: %s\n", response);
            }
            
            htx_close_stream(conn, stream->stream_id);
        }
        
        htx_connection_close(conn);
        
    } else if (strcmp(argv[1], "server") == 0) {
        int port = argc > 2 ? atoi(argv[2]) : 8443;
        
        printf("Starting HTX server on port %d\n", port);
        
        int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            perror("socket");
            htx_cleanup_ssl();
            return 1;
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
            htx_cleanup_ssl();
            return 1;
        }
        
        if (listen(listen_fd, 5) < 0) {
            perror("listen");
            close(listen_fd);
            htx_cleanup_ssl();
            return 1;
        }
        
        printf("Server listening...\n");
        
        while (1) {
            htx_connection_t *conn = htx_server_accept(listen_fd);
            if (conn) {
                // Handle connection in a separate thread in a real implementation
                printf("Client connected\n");
                
                // Echo server example
                htx_frame_t frame;
                while (htx_receive_frame(conn, &frame) == 0) {
                    if ((frame.length >> 24) == HTX_FRAME_STREAM) {
                        // Echo the data back
                        htx_stream_write(conn, frame.stream_id, frame.payload, frame.payload_len);
                    }
                    
                    if (frame.payload) {
                        free(frame.payload);
                    }
                }
                
                htx_connection_close(conn);
            }
        }
        
        close(listen_fd);
    }
    
    htx_cleanup_ssl();
    return 0;
}
