// encryption.h
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <Arduino.h>
enum EncryptionAlgorithm {
    CAESAR,
    XOR,
    VIGENERE
};

class Encryption {
public:
    static EncryptionAlgorithm currentAlgorithm;
    static String vigenereKey;
    static int shiftKey;
    static String lastEncryptedMessage; // Storage for last encrypted message
    
    static String caesarCipher(String text, int shift, bool decrypt);
    static String xorCipher(String text, char key);
    static String vigenereCipher(String text, String key, bool decrypt);
    static void startEncryptMode();
    static void startDecryptMode();
    static void changeAlgorithm();
    static void changeVigenereKey();
    static void sendEncryptedMessage();
    static void sendByte(byte data); 
    
private:
    static bool isAlpha(char c);
    static bool isUpperCase(char c);
    static const unsigned long debounceDelay = 50;
};

#endif