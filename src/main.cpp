#include <Arduino.h>
#include <NimBLEDevice.h>
#include "MessageBase.h"
#include <json.hpp>
#include <queue>
#include "ArduinoLog.h"
#include "CommandManager.h"
#include <unordered_map>
#include <unordered_set>
#include <SPIFFS.h>
#include <string>
#include "TemperatureMonitor.h"
#include <vector>

#include "ReqRes.h"
#include "Blelock.h"

BleLock key("BleKey");
std::string getMacSelf()
{
    return key.getMacAddress();
}

struct RegServerKey {
    std::string macAdr;
    std::string characteristicUUID;
};

using json = nlohmann::json;

// To convert RegServerKey to JSON
void to_json(json &j, const RegServerKey &rsk) {
    j = json{{"macAdr",             rsk.macAdr},
             {"characteristicUUID", rsk.characteristicUUID}};
}

// To convert JSON to RegServerKey
void from_json(const json &j, RegServerKey &rsk) {
    j.at("macAdr").get_to(rsk.macAdr);
    j.at("characteristicUUID").get_to(rsk.characteristicUUID);
}

#define DeviceFile "devices.json"

class ServerReg {
    std::unordered_map<std::string, RegServerKey> uniqueServers;

public:
    void serialize() {
        json j;
        for (const auto &kv: uniqueServers) {
            j[kv.first] = kv.second;
        }

        File file = SPIFFS.open(DeviceFile, FILE_WRITE);
        if (!file) {
            Serial.println("Failed to open file for writing");
            return;
        }

        file.print(j.dump().c_str());
        file.close();
    }

    void deserialize() {
        File file = SPIFFS.open(DeviceFile, FILE_READ);
        if (!file) {
            Serial.println("Failed to open file for reading");
            return;
        }

        size_t size = file.size();
        if (size == 0) {
            file.close();
            return;
        }

        std::unique_ptr<char[]> buf(new char[size]);
        file.readBytes(buf.get(), size);

        json j = json::parse(buf.get());
        uniqueServers.clear();
        for (auto &el: j.items()) {
            uniqueServers[el.key()] = el.value().get<RegServerKey>();
        }

        file.close();
    }

    bool getServerDataFirst( std::string &name/*, RegServerKey &val*/) {
        if (!uniqueServers.empty()){
            name = (*uniqueServers.begin()).first;        
            //val = (*uniqueServers.begin()).second;
            return true;
        }
        return false;
    }

    bool getServerData(const std::string &name, RegServerKey &val) {
        if (uniqueServers.find(name) != uniqueServers.end()) {
            val = (*uniqueServers.find(name)).second;
            return true;
        }
        return false;
    }

    void insert(const std::string &name, RegServerKey &val) {
        uniqueServers.insert_or_assign(name, val);
        serialize();
    }

    void remove(const std::string &name) {
        auto a = uniqueServers.find(name);
        if (a != uniqueServers.end())
            uniqueServers.erase(a);
    }

    ServerReg() = default;

    ~ServerReg() = default;
};

ServerReg regServer;
std::string getMacAddress()
{
    std::string name;
    regServer.getServerDataFirst(name);
    return name;
}


// UUIDs
static BLEUUID serviceUUID("abcd");
static BLEUUID publicCharUUID("1234");

NimBLEAdvertisedDevice *advDevice = nullptr;
std::string uniqueUUID;
//QueueHandle_t incomingQueue;
QueueHandle_t outgoingQueue;

CommandManager commandManager;

void connectToServer();

// Custom log prefix function with colors and timestamps
void logPrefix(Print *_logOutput, int logLevel) {
    const char *colorReset = "\x1B[0m";
    const char *colorFatal = "\x1B[31m";
    const char *colorError = "\x1B[91m";
    const char *colorWarning = "\x1B[93m";
    const char *colorNotice = "\x1B[94m";
    const char *colorTrace = "\x1B[92m";
    const char *colorVerbose = "\x1B[96m";

    switch (logLevel) {
        case 0:
            _logOutput->print("S: ");
            break;
        case 1:
            _logOutput->print(colorFatal);
            _logOutput->print("F: ");
            break;
        case 2:
            _logOutput->print(colorError);
            _logOutput->print("E: ");
            break;
        case 3:
            _logOutput->print(colorWarning);
            _logOutput->print("W: ");
            break;
        case 4:
            _logOutput->print(colorNotice);
            _logOutput->print("N: ");
            break;
        case 5:
            _logOutput->print(colorTrace);
            _logOutput->print("T: ");
            break;
        case 6:
            _logOutput->print(colorVerbose);
            _logOutput->print("V: ");
            break;
        default:
            _logOutput->print("?: ");
            break;
    }

    _logOutput->print(millis());
    _logOutput->print(": ");
}

void logSuffix(Print *_logOutput, int logLevel) {
    const char *colorReset = "\x1B[0m";
    _logOutput->print(colorReset);
    _logOutput->println();
}
/*
enum class LColor {
    Reset,
    Red,
    LightRed,
    Yellow,
    LightBlue,
    Green,
    LightCyan
};*/

void logColor(LColor color, const __FlashStringHelper *format, ...) {
    const char *colorCode;

    switch (color) {
        case LColor::Reset:
            colorCode = "\x1B[0m";
            break;
        case LColor::Red:
            colorCode = "\x1B[31m";
            break;
        case LColor::LightRed:
            colorCode = "\x1B[91m";
            break;
        case LColor::Yellow:
            colorCode = "\x1B[93m";
            break;
        case LColor::LightBlue:
            colorCode = "\x1B[94m";
            break;
        case LColor::Green:
            colorCode = "\x1B[92m";
            break;
        case LColor::LightCyan:
            colorCode = "\x1B[96m";
            break;
        default:
            colorCode = "\x1B[0m";
            break;
    }

    Serial.print("\n");
    Serial.print(millis());
    Serial.print("ms: ");
    Serial.print(colorCode);

    char buffer[256];
    va_list args;
    va_start(args, format);
    vsnprintf_P(buffer, sizeof(buffer), reinterpret_cast<const char *>(format), args);
    va_end(args);

    Serial.print(buffer);
    Serial.print("\x1B[0m");
    Serial.println();
}

/**************************/
SecureConnection con;

//QueueHandle_t outgoingQueue;
QueueHandle_t responseQueue;
#if 0
MessageBase* BleLock_request(MessageBase* requestMessage, const std::string& destAddr, uint32_t timeout)  {
    requestMessage->sourceAddress ="";// macAddress; // Use the stored MAC address
    requestMessage->destinationAddress = destAddr;
    requestMessage->requestUUID = requestMessage->generateUUID(); // Generate a new UUID for the request

    if (xQueueSend(outgoingQueue, &requestMessage, portMAX_DELAY) != pdPASS) {
        Log.error(F("Failed to send request to the outgoing queue"));
        return nullptr;
    }

    uint32_t startTime = xTaskGetTickCount();
    std::string* receivedMessage;

    while (true) {
        uint32_t elapsed = xTaskGetTickCount() - startTime;
        if (elapsed >= pdMS_TO_TICKS(timeout)) {
            // Timeout reached
            return nullptr; 
        }

        // Peek at the queue to see if there is a message
        if (xQueuePeek(responseQueue, &receivedMessage, pdMS_TO_TICKS(timeout) - elapsed) == pdTRUE) {
            // Create an instance of MessageBase from the received message
            MessageBase* instance = MessageBase::createInstance(*receivedMessage);

            // Check if the source address and requestUUID match
            if (instance->sourceAddress == destAddr && instance->requestUUID == requestMessage->requestUUID) {
                // Remove the item from the queue after confirming the source address and requestUUID match
                xQueueReceive(responseQueue, &receivedMessage, 0);
                delete receivedMessage; // Delete the received message pointer
                return instance;
            }
            delete instance;
        }
    }

    return nullptr; // This should never be reached, but it's here to satisfy the compiler
}
#endif
/**************/

class AdvertisedDeviceCallbacks : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice *advertisedDevice) override {
        logColor(LColor::Green, F("Found device: %s (%s)"), advertisedDevice->toString().c_str(), advertisedDevice->getName().c_str() );
        if (advertisedDevice->haveServiceUUID())
        {
            logColor(LColor::Green, F("Service device: %d === %s"), (int)advertisedDevice->isAdvertisingService(serviceUUID), serviceUUID.toString().c_str());
        }
        else
        {
            logColor(LColor::Green, F("No service"));
        }
        //if(advertisedDevice->getName() == "BleLock"){
        if (advertisedDevice->haveServiceUUID() && advertisedDevice->isAdvertisingService(serviceUUID)) {
            logColor(LColor::Green, F("Found device: %s"), advertisedDevice->toString().c_str());
            advDevice = advertisedDevice;
            if (advDevice->getName() == "BleLock") {
                NimBLEDevice::getScan()->stop();
                commandManager.sendCommand("connectToServer");
            }
        }
    }
};

NimBLEClient *pClient = nullptr;
    bool isConnected = false;

class ClientCallbacks : public NimBLEClientCallbacks {
    void onConnect(NimBLEClient *pclient) override {
        Log.notice("Connected to the server.");
        commandManager.sendCommand("onConnect");
        isConnected = true;
    };

    void onDisconnect(NimBLEClient *pclient) override {
        isConnected = false;
        Log.notice("Disconnected from the server.");
        commandManager.sendCommand("onDisconnect");
    };
};

void onNotify(NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData, size_t length, bool isNotify) {
        Log.notice("onNotify NimBLERemoteCharacteristic");
    //std::string data((char *) pData, length);
    extern std::string servMac;
    std::string *data = new std::string((char *) pData, length);
    std::string *addr = new std::string (servMac);
    std::tuple<std::string *, std::string *> *messageAndMac = new std::tuple<std::string *, std::string *>(data,addr); 

    logColor (LColor::Yellow, F("Notification: %s"), data->c_str());
    if (xQueueSend(key.jsonParsingQueue, &messageAndMac, portMAX_DELAY) != pdPASS)
    {
        logColor (LColor::Yellow, F("Notification NOT stored"));
    }
    else
        {
        logColor (LColor::Yellow, F("Notification stored"));
    }

    /*
    auto msg = MessageBase::createInstance(data);
    if (msg) {
        xQueueSend(responseQueue, &msg, portMAX_DELAY);
    }*/
}

NimBLERemoteCharacteristic *pUniqueChar = nullptr;

static bool isNeedSubscribe = false;
NimBLERemoteCharacteristic *pUniqueCharExt=nullptr;

[[noreturn]] void connectionLoopTask(void *parameter) {
    while (true) {
        //logColor(LColor::LightBlue, F("Try subscribe2"));
        if (pClient != nullptr && isNeedSubscribe) 
        {
            NimBLERemoteService *pService = pClient->getService(serviceUUID);      

            if (pService) {
                NimBLERemoteCharacteristic *pUniqueChar = pService->getCharacteristic(uniqueUUID);
                if (pUniqueChar) {
                    pUniqueChar->subscribe(true, [](NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData, size_t length, bool isNotify) {
                        logColor(LColor::LightRed, F("OnNotify"));
                        onNotify(pBLERemoteCharacteristic, pData, length, isNotify);
                    });
                    logColor(LColor::Green, F("Subscribed to unique characteristic %s"), uniqueUUID.c_str());
                    isNeedSubscribe = false;
                    // init message loop
                    pUniqueCharExt = pUniqueChar;
                    
                    //ReqRegKey *msg = new ReqRegKey;
                    //msg->processRequest (&key);
                }
                else
                {
                    logColor(LColor::Red, F("Subscribed to unique characteristic %s failure - reconnect"), uniqueUUID.c_str());
                    pClient->disconnect();
                }
            }
        }
        vTaskDelay(200 / portTICK_PERIOD_MS);
    }
}

/**
[noreturn] void proccessMessageTask ()
{
    while (true) {
        MessageBase *result = MessageBase::processRequest(nullptr);
        if (result!=nullptr)
            xQueueCRSend(outgoingQueue,&result,portMAX_DELAY);
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}
*/
[[noreturn]] void sendOpenTask (void *parameter)
{
    while (true) {
        if (key.secureConnection.aesKeys.size() > 0)
        {
            OpenRequest *msg = new OpenRequest;
            msg->processRequest (&key);
        }
        vTaskDelay(10000 / portTICK_PERIOD_MS);
    }
}

[[noreturn]] void generateRandomCommandsLoopTask(void *parameter) {
    while (true) {
        if (pClient != nullptr)
        {
            // connected
            // get characteristic 
            NimBLERemoteService *pService = pClient->getService(serviceUUID);
            if (pService!=nullptr)
            {
                NimBLERemoteCharacteristic *pUniqueChar = pService->getCharacteristic(uniqueUUID);
                if (pUniqueChar) 
                {
                    std::string randoCommand;
                    int nRandVal = random(2);
                    if (nRandVal==0)
                        randoCommand = "open";
                    else
                        randoCommand = "close";

                    pUniqueChar->writeValue (randoCommand.c_str());
                }
            }
        } 
        vTaskDelay(10000 / portTICK_PERIOD_MS);
    }
}

ClientCallbacks *clientCbk = nullptr;
bool isOkRes = false;
std::string servMac;

/*
static void notifyCallback(
  BLERemoteCharacteristic* pBLERemoteCharacteristic,
  uint8_t* pData,
  size_t length,
  bool isNotify)
{
    logColor(LColor::LightRed, F("OnNotify"));
    onNotify(pBLERemoteCharacteristic, pData, length, isNotify);
}
*/

static auto notifyCallback = [&](
    BLERemoteCharacteristic* pBLERemoteCharacteristic,
    uint8_t* pData,
    size_t length,
    bool isNotify)
{
    logColor(LColor::LightRed, F("OnNotify"));
    onNotify(pBLERemoteCharacteristic, pData, length, isNotify);
};


void connectToServer() {
        logColor(LColor::Green, F("Try Connected to server"));
    if (pClient == nullptr) 
        pClient = NimBLEDevice::createClient();
            
    if (clientCbk==nullptr)
        clientCbk = new ClientCallbacks();
    pClient->setClientCallbacks(clientCbk, false);

    if (pClient->connect(advDevice)) 
    {
        logColor(LColor::Green, F("Connected to server"));

        NimBLERemoteService *pService = pClient->getService(serviceUUID);
        if (pService) {
            NimBLERemoteCharacteristic *pPublicChar = pService->getCharacteristic(publicCharUUID);
            if (pPublicChar) {
                std::string data = pPublicChar->readValue();
                uniqueUUID = data;

                std::string mac = advDevice->getAddress().toString();
                RegServerKey reg;
                reg.characteristicUUID = uniqueUUID;
                reg.macAdr = mac;
                servMac = mac;

                int length = reg.characteristicUUID.length();
                char temp[128];
                memset(temp,0,128);
                memcpy (temp, reg.macAdr.c_str(), length);
                regServer.insert(mac, reg);
                logColor(LColor::Yellow, F("reg - %s --- %s\r\n"), reg.macAdr.c_str(), temp);

                //vTaskDelay(100/portTICK_PERIOD_MS);

                std::vector<NimBLERemoteCharacteristic *> *listOfCharacteristics = pService->getCharacteristics();
                for (int i =0; i < listOfCharacteristics->size(); i++)
                {
                    std::string str = (*listOfCharacteristics)[i]->getUUID().toString();
                    memset(temp,0,128);
                    memcpy (temp, str.c_str(), str.length());
                    logColor(LColor::LightBlue, F("%d characteristic - %s"),i, temp);
                }
                

                logColor(LColor::Yellow, F("Get characteristic"));
                pUniqueChar = pService->getCharacteristic(uniqueUUID);
                if (pUniqueChar) {
                    logColor(LColor::LightCyan, F("Try subscribe to characteristic. Can notify = %d"),pUniqueChar->canNotify());
                    bool success = pUniqueChar->subscribe(true,notifyCallback);
                                           //[](NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData,
                                           //   size_t length, bool isNotify) {
                                           //     logColor(LColor::LightRed, F("OnNotify"));
                                           //     onNotify(pBLERemoteCharacteristic, pData, length, isNotify);
                                           //});                    
                    if (success) {
                        //uint8_t val[] = {0x01, 0x00}; 
                        //if(!notifications) 
                        //val[0] = 0x02; 
                        //BLERemoteDescriptor* desc = pUniqueChar->getDescriptor(BLEUUID((uint16_t)0x2902)); 
                        //desc->writeValue(val, 2); 
                        
                        logColor(LColor::Green, F("Subscribed to unique characteristic"));
                        pUniqueCharExt = pUniqueChar;

                        ReqRegKey *req =  new ReqRegKey;
                        req->destinationAddress= mac;
                        req->sourceAddress = getMacSelf();
                        //std::string *pStr = new std::string;
                        //*pStr = req.serialize();
                        xQueueSend (outgoingQueue, &req, portMAX_DELAY);
                    }
                    else{
                        logColor(LColor::Red, F("Subscribe to characteristic failed"));
                        pClient->disconnect();
                    }
                }
                else
                {
                    logColor(LColor::Red, F("Subscribe to characteristic fail no characteristic found"));
                    //isNeedSubscribe=true;
                    pClient->disconnect();
                }
                    
            }
        }
    }
}

NimBLEScan *pScan=nullptr;


[[noreturn]] void scenrioTempTask (void *parameters)
{
    while (true)
    {
        if (isOkRes)
        {
            OpenRequest *msg = new OpenRequest;
            msg->destinationAddress = servMac;
            msg->sourceAddress = key.getMacAddress();
            //std::string *pStr = new std::string;
            //*pStr = msg.serialize();
            xQueueSend (outgoingQueue, &msg, portMAX_DELAY);
        }
        vTaskDelay (5000/ portTICK_PERIOD_MS);
    }
}


void setup() {

    Serial.begin(115200);
    Log.begin(LOG_LEVEL_VERBOSE, &Serial);
    Log.setPrefix(&logPrefix);
    Log.setSuffix(&logSuffix);
    logColor(LColor::Green, F("Starting setup..."));
    SPIFFS.begin(true);
    delay(10000);

    regServer.deserialize();

    NimBLEDevice::init("clientBleTest");
    key.setup();

    responseQueue = key.responseQueue;//xQueueCreate(10, sizeof(MessageBase *));
    outgoingQueue = key.outgoingQueue; //xQueueCreate(10, sizeof(MessageBase *));

    //xTaskCreate(connectionLoopTask, "connectionLoopTask", 8192, nullptr, 1, nullptr);
     xTaskCreate(sendOpenTask, "sendOpenTask", 8192, nullptr, 1, nullptr);

    pScan = NimBLEDevice::getScan();

    commandManager.registerHandler("connectToServer", []() {
        connectToServer();
    });

    commandManager.registerHandler("rescanToServer", []() {
        //connectToServer();
        logColor(LColor::Green, F("Handled rescanToServer event"));

        extern NimBLEScan *pScan;
        pScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks());
        pScan->setActiveScan(true);
        pScan->start(30, false);
    });

    commandManager.registerHandler("onConnect", []() {
        logColor(LColor::Green, F("Handled onConnect event"));
    });

    commandManager.registerHandler("onDisconnect", []() {
        logColor(LColor::Yellow, F("Handled onDisconnect event, attempting to reconnect..."));
        commandManager.sendCommand("rescanToServer");
        //commandManager.sendCommand("connectToServer");
    });

    commandManager.startProcessing();

    xTaskCreate(scenrioTempTask, "scenrioTempTask", 8192, nullptr, 1, nullptr);
    

    pScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks());
    pScan->setActiveScan(true);
    pScan->start(30, false);
    

}

void loop() {
    // Main loop can be empty, tasks handle the work
    
        static unsigned long lastTempCheck = 0;
    if (millis() - lastTempCheck >= 10000) {
        float temperature = TemperatureMonitor::getTemperature();

        char temperatureStr[10];
        dtostrf(temperature, 6, 2, temperatureStr);

        Log.notice(F("CPU Temperature: %s В°C"), temperatureStr);

        size_t freeHeap = esp_get_free_heap_size();
        // Print the free heap memory to the Serial Monitor
        logColor(LColor::Yellow, F("Free heap memory:  %d bytes"), freeHeap);
        lastTempCheck = millis();
    }
    
}
