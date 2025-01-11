// password.cpp
#include "password.h"
#include "pins.h"
#include <EEPROM.h>

String Password::password = "1234";
String Password::inputPassword = "";
int Password::attempts = 0;
int Password::passwordLength = 12;
bool Password::passwordGenerated = false;

extern LiquidCrystal_I2C lcd;




void Sound::beep(int duration) {
    tone(buzzerPin, 1000);
    delay(duration);
    noTone(buzzerPin);
    delay(200);
}

void Sound::alertSound() {
    Serial.println("🔊 Alarma Activă!");
    for (int i = 0; i < 10; i++) {
        beep(500);
    }
}

String Password::generatePassword(int length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    String password = "";
    for (int i = 0; i < length; i++) {
        password += charset[random(0, sizeof(charset) - 1)];
    }
    return password;
}

void Password::savePasswordToEEPROM(String newPassword) {
    for (int i = 0; i < newPassword.length(); i++) {
        EEPROM.write(i, newPassword[i]);
    }
    EEPROM.write(newPassword.length(), '\0');
}

String Password::readPasswordFromEEPROM() {
    String storedPassword = "";
    char ch;
    for (int i = 0; i < 20; i++) {
        ch = EEPROM.read(i);
        if (ch == '\0') break;
        storedPassword += ch;
    }
    return storedPassword;
}

void Password::login() {
    inputPassword = ""; // Make sure we start fresh
    Serial.flush();
    while (attempts < 3) {
        if (Serial.available() > 0) {
            char c = Serial.read();
            Serial.print("Read character: "); // Debug print
            Serial.println(c);
            
            if (c == '\n') {
                Serial.print("Checking password: '");
                Serial.print(inputPassword);
                Serial.print("' against '");
                Serial.print(password);
                Serial.println("'");
                
                if (inputPassword == password) {
                    Serial.println("✅ Acces Permis!");
                    lcd.clear();
                    lcd.print("Acces Permis!");
                    digitalWrite(greenLED, HIGH);
                    digitalWrite(redLED, LOW);
                    noTone(buzzerPin);
                    delay(2000);
                    lcd.clear();
                    return;
                } else {
                    attempts++;
                    Serial.println("❌ Parola Gresita!");
                    lcd.clear();
                    lcd.print("Parola Gresita!");
                    Sound::beep(300);
                    delay(1000);
                    lcd.setCursor(0, 0);
                    lcd.print("Introdu Parola:");
                    inputPassword = "";
                }
            } else {
                inputPassword = inputPassword + c; // Try explicit concatenation
                Serial.print("Current input: "); // Debug print
                Serial.println(inputPassword);
            }
        }
    }
    
    // Rest of the function remains the same...
}

void Password::startChangePassword() {
    lcd.clear();
    lcd.print("Schimba Parola");
    lcd.setCursor(0, 1);
    lcd.print("Parola veche:");
    Serial.println("Introduceti parola veche:");
    String oldPass = "";

    while (true) {
        if (Serial.available() > 0) {
            char c = Serial.read();
            if (c == '\n') {
                if (oldPass == password) {
                    lcd.clear();
                    lcd.print("Parola noua:");
                    Serial.println("Introduceti parola noua:");
                    String newPass = "";
                    while (!Serial.available()) {
                        delay(100);
                    }
                    while (Serial.available() > 0) {
                        char nc = Serial.read();
                        if (nc == '\n') {
                            password = newPass;
                            savePasswordToEEPROM(password);
                            lcd.clear();
                            lcd.print("Parola schimbata!");
                            Serial.println("Parola a fost schimbata cu succes!");
                            delay(2000);
                            return;
                        }
                        newPass += nc;
                    }
                } else {
                    lcd.clear();
                    lcd.print("Parola gresita!");
                    Serial.println("Parola veche este gresita!");
                    delay(2000);
                    return;
                }
            } else {
                oldPass += c;
            }
        }
    }
}