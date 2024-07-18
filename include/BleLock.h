#ifndef BLE_LOCK_H
#define BLE_LOCK_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <NimBLEDevice.h>
#include <json.hpp>
#include <SPIFFS.h>
#include "ArduinoLog.h"
#include "MessageBase.h"

#include "SecureConnection.h"
//#include <WiFi.h>

using json = nlohmann::json;
/**
enum class LColor {
    Reset,
    Red,
    LightRed,
    Yellow,
    LightBlue,
    Green,
    LightCyan
};
void logColor(LColor color, const __FlashStringHelper *format, ...) ;
*/
class BleLock {
public:
    explicit BleLock(std::string keyName);
    
    void setup();

    void handlePublicCharacteristicRead(NimBLECharacteristic *pCharacteristic, const std::string& mac);

    MessageBase* processRequest(void* context);

    QueueHandle_t outgoingQueue;
    QueueHandle_t responseQueue;

    std::string memoryFilename;
    uint32_t autoincrement;
    std::string lockName;
    SemaphoreHandle_t bleMutex{};
    BLEServer *pServer;
    BLEService *pService;
    BLECharacteristic *pPublicCharacteristic;

    QueueHandle_t jsonParsingQueue{};

    SecureConnection secureConnection;

    std::string getMacAddress ()
    {
        //if (macAddress.empty())
        //  macAddress  = WiFi.macAddress().c_str();
        return macAddress;
    }

    MessageBase *request(MessageBase *requestMessage, const std::string &destAddr, uint32_t timeout) const;

    std::string temporaryField;
    void initializeMutex();

    static std::unordered_map<std::string, std::string> messageControll; // map for multypart messages

private:
    [[noreturn]] static void outgoingMessageTask(void *pvParameter);

    [[noreturn]] static void jsonParsingTask(void *pvParameter);

    QueueHandle_t getOutgoingQueueHandle() const;

    std::string macAddress;
    std::string key;
};

#endif // BLE_LOCK_H
