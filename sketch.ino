// sketch.ino
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <EEPROM.h>
#include "pins.h"

#include "menu.h"
#include "encryption.h"
#include "password.h"


// Initialize LCD - this needs to be global as it's used by multiple classes
LiquidCrystal_I2C lcd(0x27, 16, 2);

int sex;
void setup() {
    // Initialize pins
    pinMode(buttonPin, INPUT_PULLUP);
    pinMode(selectPin, INPUT_PULLUP);
    pinMode(greenLED, OUTPUT);
    pinMode(redLED, OUTPUT);
    pinMode(buzzerPin, OUTPUT);
    
    // Start serial communication
    Serial.begin(9600);

    // Initialize LCD
    lcd.init();
    lcd.backlight();
    randomSeed(analogRead(0));
    
    // Initial display
    lcd.clear();
    lcd.print("Sistem Securizat");
    lcd.setCursor(0, 1);
    lcd.print("Introdu Parola:");

    // Check EEPROM initialization flag
    if (EEPROM.read(100) != 0xAA) {
        Serial.println("EEPROM neinitializat. Setez parola default.");
        Password::password = "1234";
        Password::savePasswordToEEPROM(Password::password);
        EEPROM.write(100, 0xAA);
    } else {
        Password::password = Password::readPasswordFromEEPROM();
        Serial.println("Parola citita din EEPROM: " + Password::password);
    }

    Serial.println("=== Sistem Criptare/Decriptare ===");
    Serial.println("Introdu Parola:");
    
    // Initial login
    Password::login();
    Menu::showMainMenu();
}

void loop() {
    Menu::handleButtonPress();
    Menu::handleSelectButton();
}