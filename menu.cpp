// menu.cpp
#include "menu.h"
#include "encryption.h"
#include "password.h"
#include "pins.h"
// extern LiquidCrystal_I2C lcd;

// Initialize static members
String Menu::mainMenuItems[MENU_ITEMS] = {
    "1.Criptare",
    "2.Decriptare",
    "3.Setari",
    "4.Schimba Parola",
    "5.Algoritm",
    "6.Cheie Vigenere",
    "7.Genereaza Parola",
    "8.Trimite Mesaj"  // New option
};
int Menu::menuIndex = 0;
MenuState Menu::currentState = MAIN_MENU;

// Button control variables initialization
int Menu::buttonState = HIGH;
int Menu::lastButtonState = HIGH;
int Menu::selectState = HIGH;
int Menu::lastSelectState = HIGH;
unsigned long Menu::lastDebounceTime = 0;

void Menu::showMainMenu() {
    lcd.clear();
    lcd.print(mainMenuItems[menuIndex]);
    lcd.setCursor(0, 1);
    lcd.print("Select->Confirma");
}

void Menu::executeMenuItem() {
    switch (menuIndex) {
        case 0:
            currentState = ENCRYPT_MODE;
            Encryption::startEncryptMode();
            break;
        case 1:
            currentState = DECRYPT_MODE;
            Encryption::startDecryptMode();
            break;
        case 2:
            currentState = SETTINGS;
            showSettings();
            break;
        case 3:
            currentState = CHANGE_PASSWORD;
            Password::startChangePassword();
            currentState = MAIN_MENU;
            showMainMenu();
            break;
        case 4:
            Encryption::changeAlgorithm();
            break;
        case 5:
            Encryption::changeVigenereKey();
            break;
        case 6:
            generatePasswordMenu();
            break;
        case 7:
            Encryption::sendEncryptedMessage();
            break;
    }
}

void Menu::handleButtonPress() {
    int reading = digitalRead(buttonPin);

    if (reading != lastButtonState) {
        lastDebounceTime = millis();
    }

    if ((millis() - lastDebounceTime) > debounceDelay) {
        if (reading != buttonState) {
            buttonState = reading;

            if (buttonState == LOW) {
                menuIndex = (menuIndex + 1) % MENU_ITEMS;
                showMainMenu();
            }
        }
    }
    lastButtonState = reading;
}

void Menu::handleSelectButton() {
    int reading = digitalRead(selectPin);

    if (reading != lastSelectState) {
        lastDebounceTime = millis();
    }

    if ((millis() - lastDebounceTime) > debounceDelay) {
        if (reading != selectState) {
            selectState = reading;

            if (selectState == LOW) {
                executeMenuItem();
            }
        }
    }
    lastSelectState = reading;
}

void Menu::generatePasswordMenu() {
    lcd.clear();
    lcd.print("Genereaza Parola");
    lcd.setCursor(0, 1);
    lcd.print("Lungime: ");
    lcd.print(Password::passwordLength);
    Password::passwordGenerated = false;

    while (currentState == MAIN_MENU) {
        int reading = digitalRead(buttonPin);
        if (reading != lastButtonState) {
            lastDebounceTime = millis();
        }

        if ((millis() - lastDebounceTime) > debounceDelay) {
            if (reading != buttonState) {
                buttonState = reading;
                if (buttonState == LOW) {
                    Password::passwordLength = (Password::passwordLength % 20) + 1;
                    lcd.setCursor(9, 1);
                    lcd.print("    ");
                    lcd.setCursor(9, 1);
                    lcd.print(Password::passwordLength);
                }
            }
        }
        lastButtonState = reading;

        if (digitalRead(selectPin) == LOW && !Password::passwordGenerated) {
            delay(debounceDelay);
            Password::passwordGenerated = true;
            String generatedPassword = Password::generatePassword(Password::passwordLength);
            lcd.clear();
            lcd.print("Parola: ");
            lcd.setCursor(0, 1);
            lcd.print(generatedPassword.substring(0, 16));
            Serial.println("Parola Generata: " + generatedPassword);
            delay(5000);
            currentState = MAIN_MENU;
            showMainMenu();
            break;
        }
    }
}

void Menu::showSettings() {
    lcd.clear();
    lcd.print("Setari");
    lcd.setCursor(0, 1);
    lcd.print("Shift Key: ");
    lcd.print(Encryption::shiftKey);

    while (currentState == SETTINGS) {
        int reading = digitalRead(buttonPin);

        if (reading != lastButtonState) {
            lastDebounceTime = millis();
        }

        if ((millis() - lastDebounceTime) > debounceDelay) {
            if (reading != buttonState) {
                buttonState = reading;

                if (buttonState == LOW) {
                    Encryption::shiftKey = (Encryption::shiftKey % 25) + 1;
                    lcd.setCursor(11, 1);
                    lcd.print("   ");
                    lcd.setCursor(11, 1);
                    lcd.print(Encryption::shiftKey);
                }
            }
        }

        lastButtonState = reading;

        if (digitalRead(selectPin) == LOW) {
            delay(debounceDelay);
            currentState = MAIN_MENU;
            showMainMenu();
        }
    }
}