// esp32_crypto.cpp
#include "esp32_crypto.h"
#include <string.h>

namespace ESP32Crypto {

void CryptoBase::generateRandomBytes(uint8_t* buffer, size_t length) {
    esp_fill_random(buffer, length);
}

// AES Implementation
AES::AES() {
    mbedtls_aes_init(&ctx);
}

AES::~AES() {
    mbedtls_aes_free(&ctx);
    memset(key, 0, KEY_SIZE_256);
    memset(iv, 0, IV_SIZE);
}

bool AES::setKey(const uint8_t* new_key, size_t length) {
    if (length != KEY_SIZE_256) return false;
    memcpy(key, new_key, KEY_SIZE_256);
    // Set the key in the context for encryption
    int ret = mbedtls_aes_setkey_enc(&ctx, key, KEY_SIZE_256 * 8);
    return ret == 0;
}

bool AES::setIV(const uint8_t* new_iv, size_t length) {
    if (length != IV_SIZE) return false;
    memcpy(iv, new_iv, IV_SIZE);
    return true;
}

bool AES::encrypt(const uint8_t* input, size_t input_len,
                 uint8_t* output, size_t* output_len,
                 Mode mode) {
    if (!input || !output || !output_len) return false;
    
    // Calculate padded length (must be multiple of 16 bytes for CBC mode)
    size_t padded_len = (input_len + 15) & ~15;
    if (padded_len > *output_len) return false;
    
    // Create a temporary buffer for padding
    uint8_t* padded_input = new uint8_t[padded_len];
    if (!padded_input) return false;
    
    // Copy input and add PKCS7 padding
    memcpy(padded_input, input, input_len);
    uint8_t padding_value = padded_len - input_len;
    memset(padded_input + input_len, padding_value, padding_value);
    
    // Temporary IV (so we don't modify the original)
    uint8_t temp_iv[16];
    memcpy(temp_iv, iv, 16);
    
    int ret;
    switch (mode) {
        case Mode::CBC:
            ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, padded_len,
                                       temp_iv, padded_input, output);
            break;
        default:
            delete[] padded_input;
            return false;
    }
    
    delete[] padded_input;
    
    if (ret == 0) {
        *output_len = padded_len;
        return true;
    }
    
    return false;
}

bool AES::decrypt(const uint8_t* input, size_t input_len,
                 uint8_t* output, size_t* output_len,
                 Mode mode) {
    if (!input || !output || !output_len) return false;
    if (input_len % 16 != 0) return false;  // Must be multiple of 16 bytes
    
    // We need a new context for decryption
    mbedtls_aes_context decrypt_ctx;
    mbedtls_aes_init(&decrypt_ctx);
    
    // Set the key for decryption
    int ret = mbedtls_aes_setkey_dec(&decrypt_ctx, key, KEY_SIZE_256 * 8);
    if (ret != 0) {
        mbedtls_aes_free(&decrypt_ctx);
        return false;
    }
    
    // Temporary IV
    uint8_t temp_iv[16];
    memcpy(temp_iv, iv, 16);
    
    // Decrypt
    ret = mbedtls_aes_crypt_cbc(&decrypt_ctx, MBEDTLS_AES_DECRYPT, input_len,
                                temp_iv, input, output);
    
    mbedtls_aes_free(&decrypt_ctx);
    
    if (ret == 0) {
        // Remove PKCS7 padding
        uint8_t padding_value = output[input_len - 1];
        if (padding_value > 16) return false;
        
        *output_len = input_len - padding_value;
        return true;
    }
    
    return false;
}

} // namespace ESP32Crypto