#include <Arduino.h>
#include <NimBLEDevice.h>
#include "MessageBase.h"
#include <json.hpp>
#include <queue>
#include "ArduinoLog.h"


#include <unordered_map>
#include <unordered_set>
#include <SPIFFS.h>
#include <string>

struct RegServerKey
{
    std::string macAdr;
    std::string characteristicUUID;
};

using json = nlohmann::json;
// To convert RegServerKey to JSON
void to_json(json& j, const RegServerKey& rsk) 
{
    j = json{{"macAdr", rsk.macAdr}, {"characteristicUUID", rsk.characteristicUUID}};
}

// To convert JSON to RegServerKey
void from_json(const json& j, RegServerKey& rsk) {
    j.at("macAdr").get_to(rsk.macAdr);
    j.at("characteristicUUID").get_to(rsk.characteristicUUID);
}
#define DeviceFile "devices.json"

class ServerReg
{
    std::unordered_map<std::string, RegServerKey > uniqueServers;

    public:
    void serialize() 
    {
        json j;
        for (const auto& kv : uniqueServers) 
        {
            j[kv.first] = kv.second;
        }

        File file = SPIFFS.open(DeviceFile, FILE_WRITE);
        if (!file) 
        {
            Serial.println("Failed to open file for writing");
            return;
        }

        file.print(j.dump().c_str());
        file.close();
    }

    void deserialize() 
    {
        File file = SPIFFS.open(DeviceFile, FILE_READ);
        if (!file) 
        {
            Serial.println("Failed to open file for reading");
            return;
        }

        size_t size = file.size();
        if (size == 0) 
        {
            file.close();
            return;
        }

        std::unique_ptr<char[]> buf(new char[size]);
        file.readBytes(buf.get(), size);

        json j = json::parse(buf.get());
        uniqueServers.clear();
        for (auto& el : j.items()) 
        {
            uniqueServers[el.key()] = el.value().get<RegServerKey>();
        }

        file.close();
    }

    bool getServerData (std::string name, RegServerKey &val)
    {
        if(uniqueServers.find(name)!=uniqueServers.end())
        {
            val = (*uniqueServers.find(name)).second;
            return true;
        }
        return false;
    }
    void insert (std::string name, RegServerKey &val)
    {
                uniqueServers.insert_or_assign(name,val);
                serialize();
    }
    void remove (std::string name)
    {
        auto a = uniqueServers.find(name);
        if (a!=uniqueServers.end())
            uniqueServers.erase (a); 
    }

    ServerReg() { }
    ~ServerReg() {}
};

ServerReg regServer;

// UUIDs
static BLEUUID serviceUUID("abcd");
static BLEUUID publicCharUUID("1234");

NimBLEAdvertisedDevice* advDevice = nullptr;
std::string uniqueUUID;
unsigned long autoincrement = 0;
QueueHandle_t incomingQueue;
QueueHandle_t outgoingQueue;

/*********************
// Цветные логи
enum class LColor {
    Reset,
    Red,
    LightRed,
    Yellow,
    LightBlue,
    Green,
    LightCyan
};

void logColor(LColor color, const __FlashStringHelper* format, ...) {
    const char* colorCode;

    switch (color) {
        case LColor::Reset: colorCode = "\x1B[0m"; break;
        case LColor::Red: colorCode = "\x1B[31m"; break;
        case LColor::LightRed: colorCode = "\x1B[91m"; break;
        case LColor::Yellow: colorCode = "\x1B[93m"; break;
        case LColor::LightBlue: colorCode = "\x1B[94m"; break;
        case LColor::Green: colorCode = "\x1B[92m"; break;
        case LColor::LightCyan: colorCode = "\x1B[96m"; break;
        default: colorCode = "\x1B[0m"; break;
    }

    Serial.print("\n");  // Add newline at the beginning
    Serial.print(millis());
    Serial.print("ms: ");
    Serial.print(colorCode);

    // Create a buffer to hold the formatted string
    char buffer[256];
    va_list args;
    va_start(args, format);
    vsnprintf_P(buffer, sizeof(buffer), reinterpret_cast<const char*>(format), args);
    va_end(args);

    Serial.print(buffer);
    Serial.print("\x1B[0m");  // Reset color
    Serial.println();
}
***/


// Custom log prefix function with colors and timestamps
void logPrefix(Print* _logOutput, int logLevel) {
    // ANSI escape codes for colors
    const char* colorReset = "\x1B[0m";
    const char* colorFatal = "\x1B[31m";    // Red
    const char* colorError = "\x1B[91m";    // Light Red
    const char* colorWarning = "\x1B[93m";  // Yellow
    const char* colorNotice = "\x1B[94m";   // Light Blue
    const char* colorTrace = "\x1B[92m";    // Green
    const char* colorVerbose = "\x1B[96m";  // Light Cyan

    switch (logLevel) {
        case 0: _logOutput->print("S: "); break;  // Silent
        case 1: _logOutput->print(colorFatal); _logOutput->print("F: "); break;  // Fatal
        case 2: _logOutput->print(colorError); _logOutput->print("E: "); break;  // Error
        case 3: _logOutput->print(colorWarning); _logOutput->print("W: "); break;  // Warning
        case 4: _logOutput->print(colorNotice); _logOutput->print("N: "); break;  // Notice
        case 5: _logOutput->print(colorTrace); _logOutput->print("T: "); break;  // Trace
        case 6: _logOutput->print(colorVerbose); _logOutput->print("V: "); break;  // Verbose
        default: _logOutput->print("?: "); break; // Unknown
    }

    // Print timestamp
    _logOutput->print(millis());
    _logOutput->print(": ");
}

void logSuffix(Print* _logOutput, int logLevel) {
    // ANSI escape codes for colors
    const char* colorReset = "\x1B[0m";
    _logOutput->print(colorReset); // Reset color
    _logOutput->println(); // Add newline
}

enum class LColor {
    Reset,
    Red,
    LightRed,
    Yellow,
    LightBlue,
    Green,
    LightCyan
};

void logColor(LColor color, const __FlashStringHelper* format, ...) {
    const char* colorCode;

    switch (color) {
        case LColor::Reset: colorCode = "\x1B[0m"; break;
        case LColor::Red: colorCode = "\x1B[31m"; break;
        case LColor::LightRed: colorCode = "\x1B[91m"; break;
        case LColor::Yellow: colorCode = "\x1B[93m"; break;
        case LColor::LightBlue: colorCode = "\x1B[94m"; break;
        case LColor::Green: colorCode = "\x1B[92m"; break;
        case LColor::LightCyan: colorCode = "\x1B[96m"; break;
        default: colorCode = "\x1B[0m"; break;
    }

    Serial.print("\n");  // Add newline at the beginning
    Serial.print(millis());
    Serial.print("ms: ");
    Serial.print(colorCode);

    // Create a buffer to hold the formatted string
    char buffer[256];
    va_list args;
    va_start(args, format);
    vsnprintf_P(buffer, sizeof(buffer), reinterpret_cast<const char*>(format), args);
    va_end(args);

    Serial.print(buffer);
    Serial.print("\x1B[0m");  // Reset color
    Serial.println();
}

static bool doConnect = false;
static bool connected = false;
static bool doScan = false;

void connectToServer();
class AdvertisedDeviceCallbacks : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) override {
        if (advertisedDevice->haveServiceUUID() && advertisedDevice->isAdvertisingService(serviceUUID)) {
            logColor(LColor::Green, F("Found device: %s"), advertisedDevice->toString().c_str());
            advDevice = advertisedDevice;
            if (advDevice->getName() == "BleLock")
            {
                NimBLEDevice::getScan()->stop();
                connectToServer ();
            }
        }
    }
};

NimBLEClient* pClient = nullptr;

class ClientCallbacks : public NimBLEClientCallbacks {
    void onConnect(NimBLEClient* pclient) {
        Log.notice("Connected to the server.");
        //connected = true;
    };

    void onDisconnect(NimBLEClient* pclient) {
        Log.notice("Disconnected from the server.");
        //connected = false;
        //doConnect = true;  // Reconnect when disconnected
        pClient == nullptr;
        connectToServer ();
    };
};


void onNotify(NimBLERemoteCharacteristic* pBLERemoteCharacteristic, uint8_t* pData, size_t length, bool isNotify) {
    std::string data((char*)pData, length);
    auto msg = MessageBase::createInstance(data);
    if (msg) {
        xQueueSend(incomingQueue, &msg, portMAX_DELAY);
    }
}

void SubcribeNew ();
const TickType_t xDelay = 1000 / portTICK_PERIOD_MS;

void sendOutgoingMessagesTask(void* parameter) {
    while (true) {
        /*MessageBase* msg;
        if (xQueueReceive(outgoingQueue, &msg, portMAX_DELAY) == pdTRUE) {
            logColor(LColor::LightBlue, F("Sending message: %s"), msg->serialize().c_str());
            // Here, you should add the code to send the message using the BLE characteristic
            // For example:
            //pUniqueChar->writeValue(msg->serialize(), false);
            delete msg;
        }*/
        logColor(LColor::LightBlue, F("Try subscribe2"));
        SubcribeNew ();
        vTaskDelay(xDelay);
    }
}

void SubcribeNew ()
{
    if (pClient == nullptr)
    {
        logColor(LColor::Yellow, F("No client..."));
        return;
    }
    logColor(LColor::Green, F("Subscribed to new characteristic..."));
    if (pClient->connect(advDevice))
    {
        NimBLERemoteService* pService = pClient->getService(serviceUUID);
        if (pService) {
            NimBLERemoteCharacteristic* pPublicChar = pService->getCharacteristic(publicCharUUID);
            if (pPublicChar) {
                std::string data = pPublicChar->readValue();
                uniqueUUID = data;

                NimBLERemoteCharacteristic* pUniqueChar = pService->getCharacteristic(uniqueUUID);
                if (pUniqueChar) {
                    pUniqueChar->subscribe(true, [](NimBLERemoteCharacteristic* pBLERemoteCharacteristic, uint8_t* pData, size_t length, bool isNotify) {
                        onNotify(pBLERemoteCharacteristic, pData, length, isNotify);
                    });
                    logColor(LColor::Green, F("Subscribed to unique characteristic %s"),uniqueUUID.c_str());
                }
            }
        }

    }

}

void connectToServer() {
    pClient = NimBLEDevice::createClient();
    if (pClient->connect(advDevice)) {
        logColor(LColor::Green, F("Connected to server"));

        NimBLERemoteService* pService = pClient->getService(serviceUUID);
        if (pService) {
            NimBLERemoteCharacteristic* pPublicChar = pService->getCharacteristic(publicCharUUID);
            if (pPublicChar) {
                std::string data = pPublicChar->readValue();
                uniqueUUID = data;

                std::string mac = advDevice->getAddress().toString();  
                RegServerKey reg;
                reg.characteristicUUID = uniqueUUID;
                reg.macAdr = mac;

                regServer.insert (mac,reg);
                logColor(LColor::Yellow, F("reg - %s --- %s"), reg.macAdr.c_str(), reg.characteristicUUID.c_str());

                NimBLERemoteCharacteristic* pUniqueChar = pService->getCharacteristic(uniqueUUID);
                if (pUniqueChar) {
                    pUniqueChar->subscribe(true, [](NimBLERemoteCharacteristic* pBLERemoteCharacteristic, uint8_t* pData, size_t length, bool isNotify) {
                        onNotify(pBLERemoteCharacteristic, pData, length, isNotify);
                    });
                    logColor(LColor::Green, F("Subscribed to unique characteristic"));
                }
            }
        }
    }
}

void setup() {
    Serial.begin(115200);
    Log.begin(LOG_LEVEL_VERBOSE, &Serial);
    Log.setPrefix(&logPrefix);
    Log.setSuffix(&logSuffix);
    logColor(LColor::Green, F("Starting setup..."));
    SPIFFS.begin(true);

    regServer.deserialize();

    // Initialize NimBLEDevice
    NimBLEDevice::init("cliebtBleTest");

    // Set up BLE scan
    NimBLEScan* pScan = NimBLEDevice::getScan();
    pScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks());
    pScan->setActiveScan(true);
    pScan->start(30, false);

    // Create queues
    incomingQueue = xQueueCreate(10, sizeof(MessageBase*));
    outgoingQueue = xQueueCreate(10, sizeof(MessageBase*));

    // Set up the task to send outgoing messages
    xTaskCreate(sendOutgoingMessagesTask, "SendOutgoingMessagesTask", 8192, NULL, 1, NULL);
}

void loop() {
    // Main loop can be empty, tasks handle the work
}



////////////////
/**
MessageBase* MessageBase::createInstance(const std::string& jsonStr) {
    try {
        nlohmann::json json = nlohmann::json::parse(jsonStr);
        std::string type = json["type"].get<std::string>();

        MessageBase* msg = nullptr;

        if (type == "reqRegKey") {
            msg = new ReqRegKey();
        } else if (type == "resOk") {
            msg = new ResOk();
        }

        if (msg) {
            msg->fromJson(json);
        }

        return msg;
    } catch (const std::exception& e) {
        Serial.print("Failed to create message instance: ");
        Serial.println ( e.what() );//<< std::endl;
        return nullptr;
    }
}

**/
