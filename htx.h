/*
* HTX (HTTP-Tunnelled Transport) Header File
*/

#ifndef HTX_H
#define HTX_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <openssl/ssl.h>

// Protocol version and constants
#define HTX_VERSION_MAJOR 1
#define HTX_VERSION_MINOR 1
#define HTX_PROTOCOL_ID "betanet/htx/1.1.0"
#define HTX_QUIC_PROTOCOL_ID "betanet/htxquic/1.1.0"

#define HTX_MAX_FRAME_SIZE 16384
#define HTX_WINDOW_SIZE 65535
#define HTX_ACCESS_TICKET_SIZE 32
#define HTX_TICKET_KEY_ID_SIZE 8
#define HTX_NONCE_SIZE 32
#define HTX_PUBKEY_SIZE 32
#define HTX_PRIVKEY_SIZE 32
#define HTX_SHARED_SECRET_SIZE 32
#define HTX_TAG_SIZE 16
#define HTX_NONCE_SALT_SIZE 12

// Crypto constants from spec
#define HTX_CHACHA20_KEY_SIZE 32
#define HTX_POLY1305_TAG_SIZE 16
#define HTX_SHA256_SIZE 32
#define HTX_X25519_KEY_SIZE 32

// Timing constants (milliseconds)
#define HTX_PING_MIN_INTERVAL 10000
#define HTX_PING_MAX_INTERVAL 60000
#define HTX_IDLE_PADDING_MIN_DELAY 200
#define HTX_IDLE_PADDING_MAX_DELAY 1200
#define HTX_IDLE_PADDING_MAX_SIZE 3072
#define HTX_REKEY_INTERVAL 3600  // 1 hour
#define HTX_REKEY_DATA_LIMIT (8ULL * 1024 * 1024 * 1024)  // 8 GiB
#define HTX_REKEY_FRAME_LIMIT (1ULL << 16)  // 2^16 frames

// Error codes
typedef enum {
    HTX_OK = 0,
    HTX_ERROR_INVALID_PARAM = -1,
    HTX_ERROR_MEMORY = -2,
    HTX_ERROR_CRYPTO = -3,
    HTX_ERROR_NETWORK = -4,
    HTX_ERROR_PROTOCOL = -5,
    HTX_ERROR_AUTH = -6,
    HTX_ERROR_TIMEOUT = -7,
    HTX_ERROR_STREAM_CLOSED = -8,
    HTX_ERROR_FLOW_CONTROL = -9
} htx_error_t;

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

// Noise XK handshake states
typedef enum {
    HTX_NOISE_INIT = 0,
    HTX_NOISE_HANDSHAKE = 1,
    HTX_NOISE_TRANSPORT = 2
} htx_noise_state_t;

// Stream states
typedef enum {
    HTX_STREAM_OPEN = 0,
    HTX_STREAM_HALF_CLOSED_LOCAL = 1,
    HTX_STREAM_HALF_CLOSED_REMOTE = 2,
    HTX_STREAM_CLOSED = 3
} htx_stream_state_t;

// Access ticket carrier types
typedef enum {
    HTX_CARRIER_COOKIE = 0,
    HTX_CARRIER_QUERY = 1,
    HTX_CARRIER_BODY = 2
} htx_carrier_type_t;

// Forward declarations
typedef struct htx_connection htx_connection_t;
typedef struct htx_stream htx_stream_t;
typedef struct htx_frame htx_frame_t;
typedef struct htx_ticket htx_ticket_t;
typedef struct htx_crypto htx_crypto_t;

// HTX frame structure
struct htx_frame {
    uint32_t length;        // 24-bit length + 8-bit type packed
    uint64_t stream_id;     // Variable-length integer
    uint8_t *payload;
    uint16_t payload_len;
};

// Access ticket structure
struct htx_ticket {
    uint8_t version;
    uint8_t cli_pub[HTX_PUBKEY_SIZE];
    uint8_t ticket_key_id[HTX_TICKET_KEY_ID_SIZE];
    uint8_t nonce32[HTX_NONCE_SIZE];
    uint8_t access_ticket[HTX_ACCESS_TICKET_SIZE];
    uint8_t *padding;
    size_t padding_len;
};

// Crypto context for inner encryption
struct htx_crypto {
    uint8_t k0c[HTX_CHACHA20_KEY_SIZE];        // Client key
    uint8_t k0s[HTX_CHACHA20_KEY_SIZE];        // Server key
    uint8_t nonce_salt_c[HTX_NONCE_SALT_SIZE]; // Client nonce salt
    uint8_t nonce_salt_s[HTX_NONCE_SALT_SIZE]; // Server nonce salt
    uint64_t counter_send;
    uint64_t counter_recv;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t frames_sent;
    uint64_t frames_recv;
    time_t last_rekey;
};

// Stream context
struct htx_stream {
    uint64_t stream_id;
    htx_stream_state_t state;
    uint32_t window_size;
    uint32_t peer_window_size;
    uint8_t *buffer;
    size_t buffer_len;
    size_t buffer_capacity;
    pthread_mutex_t mutex;
    pthread_cond_t readable;
    pthread_cond_t writable;
    time_t last_activity;
};

// Connection statistics
typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t frames_sent;
    uint64_t frames_recv;
    uint64_t streams_opened;
    uint64_t streams_closed;
    uint32_t ping_count;
    uint32_t key_updates;
    time_t connect_time;
    time_t last_activity;
} htx_stats_t;

// HTX connection context
struct htx_connection {
    int sockfd;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    htx_mode_t mode;
    htx_noise_state_t noise_state;
    htx_crypto_t crypto;
    
    htx_stream_t **streams;
    size_t stream_count;
    size_t stream_capacity;
    pthread_mutex_t streams_mutex;
    
    uint64_t next_stream_id;
    uint8_t is_client;
    uint8_t is_closing;
    
    time_t last_ping;
    time_t last_idle_padding;
    
    htx_stats_t stats;
    
    // Configuration
    struct {
        uint32_t max_frame_size;
        uint32_t window_size;
        uint16_t ping_interval;
        uint8_t enable_padding;
        uint8_t strict_origin_mirror;
    } config;
    
    // Calibration data
    struct {
        char ja3_fingerprint[256];
        char alpn_list[256];
        uint8_t h2_settings[64];
        size_t h2_settings_len;
    } calibration;
    
    pthread_mutex_t send_mutex;
    pthread_mutex_t recv_mutex;
};

// Server configuration
typedef struct {
    char *cert_file;
    char *key_file;
    uint8_t ticket_priv[HTX_PRIVKEY_SIZE];
    uint8_t ticket_pub[HTX_PUBKEY_SIZE];
    uint8_t ticket_key_id[HTX_TICKET_KEY_ID_SIZE];
    
    // Rate limiting
    uint32_t max_connections;
    uint32_t rate_limit_per_ip;
    uint32_t ticket_window_tolerance;
    
    // Security settings
    uint8_t require_pq_hybrid;  // For post-2027 requirement
    uint8_t enforce_pow;        // Proof of work requirement
    uint32_t min_pow_difficulty;
} htx_server_config_t;

// Client configuration
typedef struct {
    htx_carrier_type_t preferred_carrier;
    uint8_t enable_cover_traffic;
    uint32_t cover_connection_count;
    uint32_t retry_backoff_min;
    uint32_t retry_backoff_max;
    
    // Origin mirroring settings
    uint8_t strict_calibration;
    uint32_t calibration_timeout;
    float settings_tolerance;    // ±15% tolerance for H2 SETTINGS
} htx_client_config_t;

// Function prototypes

// Initialization and cleanup
int htx_init(void);
void htx_cleanup(void);

// Client functions
htx_connection_t *htx_client_connect(const char *host, int port, htx_mode_t mode, 
                                    const htx_client_config_t *config);
int htx_client_connect_async(const char *host, int port, htx_mode_t mode,
                            const htx_client_config_t *config, 
                            htx_connection_t **conn);

// Server functions
int htx_server_create(int port, const htx_server_config_t *config);
htx_connection_t *htx_server_accept(int listen_fd, const htx_server_config_t *config);
int htx_server_run(int listen_fd, const htx_server_config_t *config,
                  void (*handler)(htx_connection_t *));

// Connection management
void htx_connection_close(htx_connection_t *conn);
int htx_connection_ping(htx_connection_t *conn);
int htx_connection_get_stats(htx_connection_t *conn, htx_stats_t *stats);
int htx_connection_is_alive(htx_connection_t *conn);

// Stream operations
htx_stream_t *htx_stream_open(htx_connection_t *conn);
int htx_stream_close(htx_connection_t *conn, uint64_t stream_id);
int htx_stream_write(htx_connection_t *conn, uint64_t stream_id, 
                    const void *data, size_t len);
int htx_stream_read(htx_connection_t *conn, uint64_t stream_id, 
                   void *buffer, size_t buffer_size);
int htx_stream_read_timeout(htx_connection_t *conn, uint64_t stream_id,
                           void *buffer, size_t buffer_size, int timeout_ms);
int htx_stream_flush(htx_connection_t *conn, uint64_t stream_id);
int htx_stream_get_state(htx_connection_t *conn, uint64_t stream_id,
                        htx_stream_state_t *state);

// Frame operations (low-level)
int htx_send_frame(htx_connection_t *conn, const htx_frame_t *frame);
int htx_receive_frame(htx_connection_t *conn, htx_frame_t *frame);
void htx_frame_free(htx_frame_t *frame);

// Crypto operations
int htx_generate_keypair(uint8_t *public_key, uint8_t *private_key);
int htx_x25519_dh(const uint8_t *private_key, const uint8_t *public_key,
                 uint8_t *shared_secret);
int htx_hkdf_expand(const uint8_t *key, size_t key_len, 
                   const char *label, const uint8_t *info, size_t info_len,
                   uint8_t *output, size_t output_len);

// Access ticket functions
int htx_ticket_generate(htx_ticket_t *ticket, const uint8_t *ticket_pub,
                       const uint8_t *ticket_key_id);
int htx_ticket_verify(const htx_ticket_t *ticket, const uint8_t *ticket_priv,
                     const uint8_t *ticket_key_id);
int htx_ticket_encode_cookie(const htx_ticket_t *ticket, const char *site_name,
                            char *cookie_header, size_t header_size);
int htx_ticket_encode_query(const htx_ticket_t *ticket, 
                           char *query_param, size_t param_size);
int htx_ticket_decode(const char *encoded, htx_ticket_t *ticket);
void htx_ticket_free(htx_ticket_t *ticket);

// Calibration functions
int htx_calibrate_origin(const char *host, int port, 
                        void *calibration_data, size_t *data_size);
int htx_apply_calibration(SSL_CTX *ctx, const void *calibration_data, 
                         size_t data_size);

// Utility functions
const char *htx_error_string(htx_error_t error);
void htx_set_log_level(int level);
void htx_log(int level, const char *format, ...);

// Debugging and testing
int htx_connection_dump_state(htx_connection_t *conn, FILE *output);
int htx_frame_dump(const htx_frame_t *frame, FILE *output);
int htx_run_self_test(void);

// Configuration helpers
htx_client_config_t *htx_client_config_default(void);
htx_server_config_t *htx_server_config_default(void);
void htx_client_config_free(htx_client_config_t *config);
void htx_server_config_free(htx_server_config_t *config);

// Thread-safe connection pool (optional)
typedef struct htx_pool htx_pool_t;

htx_pool_t *htx_pool_create(size_t max_connections);
void htx_pool_destroy(htx_pool_t *pool);
htx_connection_t *htx_pool_get_connection(htx_pool_t *pool, const char *host, int port);
void htx_pool_return_connection(htx_pool_t *pool, htx_connection_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* HTX_H */
