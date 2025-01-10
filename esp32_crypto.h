// esp32_crypto.h
#ifndef ESP32_CRYPTO_H
#define ESP32_CRYPTO_H

#include "esp_system.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecp.h"
#include "esp_random.h"

namespace ESP32Crypto {

class CryptoBase {
protected:
    static const size_t KEY_SIZE_256 = 32;
    static const size_t IV_SIZE = 16;
    
public:
    virtual ~CryptoBase() = default;
    
    // Secure random number generation
    static void generateRandomBytes(uint8_t* buffer, size_t length);
};

class AES : public CryptoBase {
private:
    mbedtls_aes_context ctx;
    uint8_t key[KEY_SIZE_256];
    uint8_t iv[IV_SIZE];

public:
    enum class Mode {
        CBC,
        CTR,
        GCM
    };

    AES();
    ~AES();

    bool setKey(const uint8_t* key, size_t length);
    bool setIV(const uint8_t* iv, size_t length);
    
    bool encrypt(const uint8_t* input, size_t input_len,
                uint8_t* output, size_t* output_len,
                Mode mode = Mode::CBC);
                
    bool decrypt(const uint8_t* input, size_t input_len,
                uint8_t* output, size_t* output_len,
                Mode mode = Mode::CBC);
};

class SHA : public CryptoBase {
private:
    mbedtls_sha256_context ctx;

public:
    SHA();
    ~SHA();

    void init();
    void update(const uint8_t* input, size_t length);
    void final(uint8_t output[32]);
    
    // One-shot hash computation
    static void hash(const uint8_t* input, size_t length, uint8_t output[32]);
};

class RSA : public CryptoBase {
private:
    mbedtls_rsa_context ctx;
    static const int KEY_SIZE_BITS = 2048;

public:
    RSA();
    ~RSA();

    bool generateKeyPair();
    bool setPublicKey(const uint8_t* modulus, size_t mod_len,
                     const uint8_t* exponent, size_t exp_len);
    bool setPrivateKey(const uint8_t* key, size_t length);
    
    bool encrypt(const uint8_t* input, size_t input_len,
                uint8_t* output, size_t* output_len);
    bool decrypt(const uint8_t* input, size_t input_len,
                uint8_t* output, size_t* output_len);
                
    bool sign(const uint8_t* input, size_t input_len,
             uint8_t* signature, size_t* sig_len);
    bool verify(const uint8_t* input, size_t input_len,
               const uint8_t* signature, size_t sig_len);
};

class ECC : public CryptoBase {
private:
    mbedtls_ecp_group group;
    mbedtls_ecp_point public_key;
    mbedtls_mpi private_key;
    static const int CURVE = MBEDTLS_ECP_DP_SECP256R1;

public:
    ECC();
    ~ECC();

    bool generateKeyPair();
    bool setPrivateKey(const uint8_t* key, size_t length);
    bool getPublicKey(uint8_t* key, size_t* length);
    
    bool generateSharedSecret(const uint8_t* peer_public_key,
                            size_t key_len,
                            uint8_t* shared_secret,
                            size_t* secret_len);
                            
    bool sign(const uint8_t* input, size_t input_len,
             uint8_t* signature, size_t* sig_len);
    bool verify(const uint8_t* input, size_t input_len,
               const uint8_t* signature, size_t sig_len);
};

// HMAC implementation
class HMAC : public CryptoBase {
private:
    SHA sha;
    uint8_t key[KEY_SIZE_256];
    static const size_t BLOCK_SIZE = 64;

public:
    HMAC();
    ~HMAC();

    bool setKey(const uint8_t* key, size_t length);
    void generate(const uint8_t* input, size_t input_len,
                 uint8_t* output, size_t* output_len);
};

// ChaCha20-Poly1305 AEAD cipher
class ChaCha20Poly1305 : public CryptoBase {
private:
    uint8_t key[KEY_SIZE_256];
    uint8_t nonce[12];

public:
    ChaCha20Poly1305();
    ~ChaCha20Poly1305();

    bool setKey(const uint8_t* key, size_t length);
    bool setNonce(const uint8_t* nonce, size_t length);
    
    bool encrypt(const uint8_t* input, size_t input_len,
                const uint8_t* aad, size_t aad_len,
                uint8_t* output, size_t* output_len,
                uint8_t* tag, size_t tag_len);
                
    bool decrypt(const uint8_t* input, size_t input_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* tag, size_t tag_len,
                uint8_t* output, size_t* output_len);
};

// Key Derivation Function (HKDF)
class HKDF : public CryptoBase {
private:
    HMAC hmac;

public:
    HKDF();
    ~HKDF();

    bool derive(const uint8_t* input, size_t input_len,
               const uint8_t* salt, size_t salt_len,
               const uint8_t* info, size_t info_len,
               uint8_t* output, size_t output_len);
};

} // namespace ESP32Crypto

#endif // ESP32_CRYPTO_H