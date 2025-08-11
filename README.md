# Betanet Implementation

A (not-nearly) complete C implementation of the HTX protocol as specified in the [Betanet 1.1 specification](https://github.com/ravendevteam/betanet). HTX provides covert transport over TCP-443 and QUIC-443 that mimics legitimate HTTPS traffic while enabling secure, censorship-resistant communication.

## Disclaimer

This was a product of a LOT of research and very difficult to undertake, its still no where near done but it does make a server binary and client binary all-in-one and it works. I don't even know if this meets every specification because I've never attempted something like this. I'm not looking for direct payment I believe in Betanet.

## Reasoning

I'm using the PIL license just because it requires explanation on how to implement this in a server environment and how to build the binary and use its functions (and I made the PIL License). Feel free to add licenses to this as PIL can be multi-licensed, especially with (A)GPL, APACHE, and MIT.

## License

[![Custom badge](https://img.shields.io/endpoint?style=for-the-badge&url=https%3A%2F%2Fshare.jester-designs.com%2Fmedia%2Fbank%2Fkeep%2Fpil.json)](LICENSE)

## Features

### Core Protocol Support
- **Multi-transport**: TCP-443 and QUIC-443 support
- **Origin Mirroring**: TLS fingerprint calibration to match target origins
- **Access Tickets**: ECDH-based authentication with replay protection
- **Inner Encryption**: Noise XK handshake with ChaCha20-Poly1305 AEAD
- **Stream Multiplexing**: Concurrent bidirectional streams over single connection
- **Flow Control**: Per-stream and connection-level window management
- **Key Rotation**: Automatic rekeying based on time, data, and frame limits
- **Anti-correlation**: Cover traffic and retry randomization

### Security Features
- **Post-quantum Ready**: X25519-Kyber768 hybrid support (mandatory from 2027)
- **Forward Secrecy**: Ephemeral keys with regular rotation
- **Replay Protection**: Time-windowed ticket validation
- **Rate Limiting**: Multi-tier limiting (per-IP, per-AS, per-connection)
- **Traffic Analysis Resistance**: Randomized timing and padding

### Covert Transport
- **HTTP Carrier Methods**: Cookie, query parameter, and POST body embedding
- **Variable Padding**: Configurable padding to defeat size-based analysis
- **Idle Traffic**: Random padding during idle periods
- **Cover Connections**: Decoy connections to unrelated origins

## Architecture

The implementation follows a layered architecture matching the Betanet specification:

```
┌─────────────────────────────────────────────────┐
│ Application Layer (L7)                          │
├─────────────────────────────────────────────────┤
│ HTX Stream Multiplexing (L2 Application)       │
├─────────────────────────────────────────────────┤
│ Inner Noise XK Encryption (L2 Security)        │
├─────────────────────────────────────────────────┤
│ Access Ticket Authentication (L2 Auth)         │
├─────────────────────────────────────────────────┤
│ Origin-Mirrored TLS (L2 Transport)             │
├─────────────────────────────────────────────────┤
│ TCP-443 / QUIC-443 (L1)                        │
└─────────────────────────────────────────────────┘
```

## Quick Start

### Building

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install libssl-dev build-essential

# Build
make

# Or with debug symbols
make debug
```

### Basic Server

```c
#include "htx.h"

int main() {
    htx_init();
    
    htx_server_config_t *config = htx_server_config_default();
    int listen_fd = htx_server_create(8443, config);
    
    while (1) {
        htx_connection_t *conn = htx_server_accept(listen_fd, config);
        if (conn) {
            // Handle connection (typically in separate thread)
            handle_client(conn);
        }
    }
    
    htx_cleanup();
    return 0;
}
```

### Basic Client

```c
#include "htx.h"

int main() {
    htx_init();
    
    htx_client_config_t *config = htx_client_config_default();
    htx_connection_t *conn = htx_client_connect("example.com", 443, 
                                               HTX_MODE_TCP, config);
    
    if (conn) {
        htx_stream_t *stream = htx_stream_open(conn);
        htx_stream_write(conn, stream->stream_id, "Hello", 5);
        
        char response[256];
        int bytes = htx_stream_read(conn, stream->stream_id, response, 255);
        
        htx_stream_close(conn, stream->stream_id);
        htx_connection_close(conn);
    }
    
    htx_cleanup();
    return 0;
}
```

## Usage Examples

### Running the Example Program

```bash
# Start server
./htx_simple server 8443

# Connect client (in another terminal)
./htx_simple client localhost 8443 tcp

# Performance test
./htx_simple perf localhost 8443 10 100

# Run self-tests
./htx_simple test
```

### Advanced Configuration

```c
// Client with strict origin mirroring
htx_client_config_t *config = htx_client_config_default();
config->strict_calibration = 1;
config->enable_cover_traffic = 1;
config->preferred_carrier = HTX_CARRIER_COOKIE;
config->settings_tolerance = 0.15f; // ±15% for H2 SETTINGS

// Server with enhanced security
htx_server_config_t *server_config = htx_server_config_default();
server_config->require_pq_hybrid = 1;  // Force post-quantum crypto
server_config->enforce_pow = 1;         // Require proof of work
server_config->min_pow_difficulty = 22; // 22-bit PoW minimum
```

## Protocol Details

### Access Ticket Generation

Access tickets use ECDH key agreement and HKDF derivation:

1. Client generates ephemeral X25519 keypair
2. Performs ECDH with server's published ticket public key
3. Derives ticket using HKDF with hourly time-based salt
4. Embeds ticket in HTTP carrier (cookie, query, or body)

```c
htx_ticket_t ticket;
uint8_t server_ticket_pub[32]; // Server's published key
htx_ticket_generate(&ticket, server_ticket_pub, ticket_key_id);

// Encode as cookie
char cookie[1024];
htx_ticket_encode_cookie(&ticket, "example.com", cookie, sizeof(cookie));
```

### Stream Operations

HTX supports multiple concurrent streams over a single connection:

```c
// Open multiple streams
htx_stream_t *stream1 = htx_stream_open(conn);
htx_stream_t *stream2 = htx_stream_open(conn);

// Write to streams concurrently
htx_stream_write(conn, stream1->stream_id, data1, len1);
htx_stream_write(conn, stream2->stream_id, data2, len2);

// Read with timeout
char buffer[1024];
int bytes = htx_stream_read_timeout(conn, stream1->stream_id, 
                                   buffer, sizeof(buffer), 5000);
```

### Key Management

The implementation handles automatic key rotation:

```c
// Keys are automatically rotated when any condition is met:
// - 8 GiB of data transferred
// - 2^16 frames sent
// - 1 hour elapsed since last rekey

// Manual key update
htx_connection_ping(conn); // Also triggers rekey check
```

## Security Considerations

### Origin Mirroring

HTX performs pre-flight calibration to learn origin characteristics:

- JA3/JA4 TLS fingerprint matching
- ALPN negotiation mirroring  
- HTTP/2 SETTINGS parameter matching (within ±15% tolerance)
- Extension order preservation

### Traffic Analysis Resistance

- **Variable Padding**: Tickets padded to 24-64 bytes randomly
- **Idle Padding**: Random 0-3 KiB padding during idle periods
- **Cover Traffic**: Decoy connections to unrelated origins on retry
- **Timing Randomization**: Jittered intervals for all periodic operations

### Rate Limiting

Multi-tier rate limiting prevents abuse:

```c
// Server configuration
config->rate_limit_per_ip = 10;        // Max 10 conn/min per IP
config->max_connections = 1000;        // Global connection limit
config->ticket_window_tolerance = 1;   // Accept tickets ±1 hour
```

## Testing

### Unit Tests

```bash
make test
./htx_simple test
```

### Integration Testing

```bash
# Terminal 1: Start server
./htx_simple server 8443

# Terminal 2: Run client tests
./htx_simple client localhost 8443 tcp
./htx_simple client localhost 8443 quic  # If QUIC implemented

# Terminal 3: Performance testing
./htx_simple perf localhost 8443 100 50
```

## Implementation Status

### Implemented
- TCP-443 transport with origin-mirrored TLS
- Access ticket generation and verification
- Inner Noise XK handshake (stub)
- Stream multiplexing and flow control
- Frame encryption/decryption with ChaCha20-Poly1305
- Automatic key rotation
- Basic rate limiting
- Example client/server programs

### Partial/Stub Implementation
- QUIC-443 transport (framework in place)
- TLS calibration (basic structure)
- Noise XK cryptography (needs full implementation)
- Post-quantum X25519-Kyber768 hybrid

### Not Yet Implemented
- SCION path selection and routing
- libp2p-v2 overlay mesh integration  
- Nym mixnet privacy hops
- Self-certifying naming system
- Cashu/Lightning payment integration
- Full governance and bootstrap system

## Dependencies

- **OpenSSL 1.1.1+**: TLS, cryptography, and key derivation
- **pthread**: Threading support
- **Standard C library**: POSIX socket APIs

### Optional Dependencies
- **libquic**: For QUIC-443 support (when implemented)
- **libsodium**: Alternative crypto backend
- **libp2p**: For overlay mesh integration

## API Reference

### Connection Management

```c
// Initialize library
int htx_init(void);
void htx_cleanup(void);

// Client connections
htx_connection_t *htx_client_connect(const char *host, int port, 
                                    htx_mode_t mode,
                                    const htx_client_config_t *config);

// Server operations  
int htx_server_create(int port, const htx_server_config_t *config);
htx_connection_t *htx_server_accept(int listen_fd, 
                                   const htx_server_config_t *config);

// Connection lifecycle
void htx_connection_close(htx_connection_t *conn);
int htx_connection_is_alive(htx_connection_t *conn);
int htx_connection_get_stats(htx_connection_t *conn, htx_stats_t *stats);
```

### Stream Operations

```c
// Stream lifecycle
htx_stream_t *htx_stream_open(htx_connection_t *conn);
int htx_stream_close(htx_connection_t *conn, uint64_t stream_id);

// Data transfer
int htx_stream_write(htx_connection_t *conn, uint64_t stream_id,
                    const void *data, size_t len);
int htx_stream_read(htx_connection_t *conn, uint64_t stream_id,
                   void *buffer, size_t buffer_size);
int htx_stream_read_timeout(htx_connection_t *conn, uint64_t stream_id,
                           void *buffer, size_t buffer_size, int timeout_ms);
```

### Configuration

```c
// Default configurations
htx_client_config_t *htx_client_config_default(void);
htx_server_config_t *htx_server_config_default(void);

// Cleanup
void htx_client_config_free(htx_client_config_t *config);
void htx_server_config_free(htx_server_config_t *config);
```

## Contributing

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/something-feature`)  
3. **Implement** changes following the coding standards
4. **Add** tests for new functionality
5. **Commit** changes (`git commit -m 'Add something feature'`)
6. **Push** to branch (`git push origin feature/something-feature`)
7. **Open** a Pull Request

### Coding Standards

- Follow K&R C style with 4-space indentation
- All functions must have header documentation
- Use `htx_` prefix for all public APIs
- Error handling using `htx_error_t` return codes
- Thread-safe by design where applicable

## Security Notice

This is a reference implementation. Before using in production:

1. **Security Audit**: Have the code reviewed by cryptography experts
2. **Penetration Testing**: Test against real-world attack scenarios  
3. **Compliance**: Ensure compliance with the specified regulations
4. **Key Management**: Implement proper key storage and rotation
5. **Monitoring**: Add comprehensive logging and monitoring

## Support and Contact

- **Issues**: Report bugs via Issues
- **Security**: Report security issues privately to the maintainers
