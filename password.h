// password.h
#ifndef PASSWORD_H
#define PASSWORD_H

#include <Arduino.h>
#include <LiquidCrystal_I2C.h>
extern LiquidCrystal_I2C lcd;
class Sound {
public:
    static void beep(int duration);
    static void alertSound();
};

class Password {
public:
    static String password;
    static String inputPassword;
    static int attempts;
    static int passwordLength;
    static bool passwordGenerated;
    
    static void login();
    static void startChangePassword();
    static String generatePassword(int length);
    static void savePasswordToEEPROM(String newPassword);
    static String readPasswordFromEEPROM();
};

#endif