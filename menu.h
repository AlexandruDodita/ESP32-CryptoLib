// menu.h
#ifndef MENU_H
#define MENU_H

#include <Arduino.h>

enum MenuState {
    MAIN_MENU,
    ENCRYPT_MODE,
    DECRYPT_MODE,
    SETTINGS,
    CHANGE_PASSWORD,
    VIEW_HISTORY
};

class Menu {
public:
    static const int MENU_ITEMS = 8; // Increased for new option
    static String mainMenuItems[MENU_ITEMS];
    static int menuIndex;
    static MenuState currentState;
    
    // Button control variables
    static int buttonState;
    static int lastButtonState;
    static int selectState;
    static int lastSelectState;
    static unsigned long lastDebounceTime;
    static const unsigned long debounceDelay = 50;
    
    // Menu methods
    static void showMainMenu();
    static void executeMenuItem();
    static void handleButtonPress();
    static void handleSelectButton();
    static void generatePasswordMenu();
    static void showSettings();
};


#endif