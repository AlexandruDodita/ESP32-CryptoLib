// crypto.ino
#include <Arduino.h>
#include "esp32_crypto.h"

using namespace ESP32Crypto;

void printHex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 16) Serial.print("0");
        Serial.print(data[i], HEX);
    }
    Serial.println();
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("Starting ESP32 Crypto Test");

    // Create an instance of AES
    AES aes;
    
    // Test data
    uint8_t test_key[32];
    uint8_t test_iv[16];
    
    // Fill test key and IV with incrementing values
    for (int i = 0; i < 32; i++) test_key[i] = i;
    for (int i = 0; i < 16; i++) test_iv[i] = i;
    
    uint8_t plaintext[] = "Hello ESP32 Crypto!";
    size_t plaintext_len = strlen((char*)plaintext);
    
    // Buffers for encrypted and decrypted data
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    size_t output_len, decrypted_len;

    Serial.println("\nTest Data:");
    Serial.print("Plaintext: ");
    Serial.println((char*)plaintext);
    
    Serial.print("Key: ");
    printHex(test_key, 32);
    Serial.print("IV: ");
    printHex(test_iv, 16);

    // Set key and IV
    bool key_set = aes.setKey(test_key, 32);
    bool iv_set = aes.setIV(test_iv, 16);

    Serial.print("Key set: ");
    Serial.println(key_set ? "Success" : "Failed");
    Serial.print("IV set: ");
    Serial.println(iv_set ? "Success" : "Failed");

    // Try encryption
    if (aes.encrypt(plaintext, plaintext_len, ciphertext, &output_len)) {
        Serial.println("\nEncryption successful!");
        Serial.print("Encrypted data (hex): ");
        printHex(ciphertext, output_len);
        
        // Try decryption
        if (aes.decrypt(ciphertext, output_len, decrypted, &decrypted_len)) {
            Serial.println("\nDecryption successful!");
            Serial.print("Decrypted text: ");
            decrypted[decrypted_len] = 0; // Null terminate
            Serial.println((char*)decrypted);
        } else {
            Serial.println("\nDecryption failed!");
        }
    } else {
        Serial.println("\nEncryption failed!");
    }
}

void loop() {
    delay(1000);
}