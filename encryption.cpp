// encryption.cpp
#include "encryption.h"
#include "pins.h"
#include "menu.h"
#include "password.h"


EncryptionAlgorithm Encryption::currentAlgorithm = CAESAR;
String Encryption::vigenereKey = "KEY";
int Encryption::shiftKey = 3;
String Encryption::lastEncryptedMessage = "";

bool Encryption::isAlpha(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool Encryption::isUpperCase(char c) {
    return (c >= 'A' && c <= 'Z');
}

String Encryption::caesarCipher(String text, int shift, bool decrypt) {
    String result = "";
    for (int i = 0; i < text.length(); i++) {
        char c = text[i];
        if (isAlpha(c)) {
            char base = isUpperCase(c) ? 'A' : 'a';
            if (decrypt) {
                result += char((c - base - shift + 26) % 26 + base);
            } else {
                result += char((c - base + shift) % 26 + base);
            }
        } else {
            result += c;
        }
    }
    lastEncryptedMessage = result;
    return result;
}

String Encryption::xorCipher(String text, char key) {
    String result = "";
    for (int i = 0; i < text.length(); i++) {
        result += (char)(text[i] ^ key);
    }
    lastEncryptedMessage = result;
    return result;
}

String Encryption::vigenereCipher(String text, String key, bool decrypt) {
    String result = "";
    int keyLength = key.length();

    for (int i = 0; i < text.length(); i++) {
        char textChar = text[i];
        char keyChar = key[i % keyLength];
        
        if (isAlpha(textChar)) {
            char base = isUpperCase(textChar) ? 'A' : 'a';
            char keyBase = isUpperCase(keyChar) ? 'A' : 'a';
            
            if (decrypt) {
                result += char((textChar - base - (keyChar - keyBase) + 26) % 26 + base);
            } else {
                result += char((textChar - base + (keyChar - keyBase)) % 26 + base);
            }
        } else {
            result += textChar;
        }
    }
    lastEncryptedMessage = result;
    return result;
}

void Encryption::startEncryptMode() {
    lcd.clear();
    lcd.print("Mod Criptare");
    lcd.setCursor(0, 1);
    lcd.print("Introdu mesaj:");
    digitalWrite(greenLED, HIGH);
    digitalWrite(redLED, LOW);

    while (Menu::currentState == ENCRYPT_MODE) {
        if (Serial.available() > 0) {
            String message = Serial.readString();
            message.trim();

            if (message.length() > 0) {
                String encrypted;
                if (currentAlgorithm == CAESAR) {
                    encrypted = caesarCipher(message, shiftKey, false);
                } else if (currentAlgorithm == XOR) {
                    encrypted = xorCipher(message, shiftKey);
                } else if (currentAlgorithm == VIGENERE) {
                    encrypted = vigenereCipher(message, vigenereKey, false);
                }

                lcd.clear();
                lcd.print("Mesaj criptat:");
                lcd.setCursor(0, 1);
                lcd.print(encrypted.substring(0, 16));

                Serial.println("== CRIPTARE ==");
                Serial.print("Mesaj Original: ");
                Serial.println(message);
                Serial.print("Mesaj Criptat: ");
                Serial.println(encrypted);

                delay(3000);
                Menu::currentState = MAIN_MENU;
                Menu::showMainMenu();
            }
        }

        if (digitalRead(selectPin) == LOW) {
            delay(Menu::debounceDelay);
            Menu::currentState = MAIN_MENU;
            Menu::showMainMenu();
        }
    }
}

void Encryption::startDecryptMode() {
    lcd.clear();
    lcd.print("Mod Decriptare");
    lcd.setCursor(0, 1);
    lcd.print("Introdu mesaj:");
    digitalWrite(greenLED, LOW);
    digitalWrite(redLED, HIGH);

    while (Menu::currentState == DECRYPT_MODE) {
        if (Serial.available() > 0) {
            String message = Serial.readString();
            message.trim();

            if (message.length() > 0) {
                String decrypted;
                if (currentAlgorithm == CAESAR) {
                    decrypted = caesarCipher(message, shiftKey, true);
                } else if (currentAlgorithm == XOR) {
                    decrypted = xorCipher(message, shiftKey);
                } else if (currentAlgorithm == VIGENERE) {
                    decrypted = vigenereCipher(message, vigenereKey, true);
                }

                lcd.clear();
                lcd.print("Mesaj decriptat:");
                lcd.setCursor(0, 1);
                lcd.print(decrypted.substring(0, 16));

                Serial.println("== DECRIPTARE ==");
                Serial.print("Mesaj Criptat: ");
                Serial.println(message);
                Serial.print("Mesaj Decriptat: ");
                Serial.println(decrypted);

                delay(3000);
                Menu::currentState = MAIN_MENU;
                Menu::showMainMenu();
            }
        }

        if (digitalRead(selectPin) == LOW) {
            delay(Menu::debounceDelay);
            Menu::currentState = MAIN_MENU;
            Menu::showMainMenu();
        }
    }
}

void Encryption::changeAlgorithm() {
    lcd.clear();
    lcd.print("Alege Algoritm:");
    lcd.setCursor(0, 1);

    int selectedAlgorithm = (int)currentAlgorithm;

    while (true) {
        if (digitalRead(buttonPin) == LOW) {
            delay(Menu::debounceDelay);
            selectedAlgorithm = (selectedAlgorithm + 1) % 3;
        }

        lcd.setCursor(0, 1);
        switch (selectedAlgorithm) {
            case 0:
                lcd.print("1. Caesar     ");
                break;
            case 1:
                lcd.print("2. XOR        ");
                break;
            case 2:
                lcd.print("3. Vigenere   ");
                break;
        }

        if (digitalRead(selectPin) == LOW) {
            delay(Menu::debounceDelay);
            currentAlgorithm = (EncryptionAlgorithm)selectedAlgorithm;
            Serial.print("Algoritm selectat: ");
            switch (currentAlgorithm) {
                case CAESAR:
                    Serial.println("Caesar");
                    break;
                case XOR:
                    Serial.println("XOR");
                    break;
                case VIGENERE:
                    Serial.println("Vigenere");
                    break;
            }
            lcd.clear();
            lcd.print("Algoritm Salvat!");
            delay(2000);
            Menu::currentState = MAIN_MENU;
            Menu::showMainMenu();
            break;
        }
    }
}

void Encryption::changeVigenereKey() {
    lcd.clear();
    lcd.print("Cheie Vigenere:");
    Serial.println("Introdu noua cheie Vigenere:");

    String newKey = "";
    while (!Serial.available()) {
        delay(100);
    }
    newKey = Serial.readString();
    newKey.trim();

    if (newKey.length() > 0) {
        vigenereKey = newKey;
        Serial.println("Cheie actualizata: " + vigenereKey);
        lcd.clear();
        lcd.print("Cheie Salvata!");
        delay(2000);
    }
    Menu::currentState = MAIN_MENU;
    Menu::showMainMenu();
}


// Add these helper functions in encryption.cpp
void Encryption::sendByte(byte data) {
    // // Send each bit, LSB first
    for (int i = 0; i < 8; i++) {
        digitalWrite(dataPinOut, (data >> i) & 1);
        delay(1);  // Small delay for stability
        digitalWrite(clockPinOut, HIGH);
        delay(1);
        digitalWrite(clockPinOut, LOW);
        delay(1);
    }
}

void Encryption::sendEncryptedMessage() {
    // Serial.println("Entered sex");
    lastEncryptedMessage = "abjabj";
    if (lastEncryptedMessage.length() == 0) {
        // lcd.clear();
        // lcd.print("Nu exista mesaj");
        // lcd.setCursor(0, 1);
        // lcd.print("Criptat!");
        delay(2000);
        Menu::currentState = MAIN_MENU;
        Menu::showMainMenu();
        return;
    }
    // lcd.clear();
    // lcd.print("Trimit mesaj...");
    
    // Setup pins
    pinMode(dataPinOut, OUTPUT);
    pinMode(clockPinOut, OUTPUT); //TODO pinurile de input si output nu sunt corect selectate/puse???
    digitalWrite(clockPinOut, LOW);
    
    // Send start sequence (0xFF as start marker)
    sendByte(0xFF);
    delay(10);
    
    // Send message length
    sendByte(lastEncryptedMessage.length());
    delay(5);
    
    // Send each character
    for (int i = 0; i < lastEncryptedMessage.length(); i++) {
        sendByte(lastEncryptedMessage[i]);
        delay(2);
    }
    
    // Send end sequence (0xFF as end marker)
    sendByte(0xFF);
    
    // Print to monitoring Serial
    // Serial.println("Mesaj trimis: " + lastEncryptedMessage);
    
    // lcd.clear();
    // lcd.print("Mesaj trimis!");
    delay(2000);
    Menu::currentState = MAIN_MENU;
    Menu::showMainMenu();
}
// Also modify startEncryptMode() to store the encrypted message:
// In the if (message.length() > 0) block, after encryption: