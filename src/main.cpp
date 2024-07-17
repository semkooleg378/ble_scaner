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

std::string getMacSelf() {
    return key.getMacAddress();
}

struct RegServerKey {
    std::string macAdr;
    std::string characteristicUUID;
};

using json = nlohmann::json;

// To convert RegServerKey to JSON
void to_json(json &j, const RegServerKey &rsk) {
    j = json{{"macAdr", rsk.macAdr}, {"characteristicUUID", rsk.characteristicUUID}};
}

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
        for (const auto &kv : uniqueServers) {
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
        for (auto &el : j.items()) {
            uniqueServers[el.key()] = el.value().get<RegServerKey>();
        }

        file.close();
    }

    bool getServerDataFirst(std::string &name) {
        if (!uniqueServers.empty()) {
            name = uniqueServers.begin()->first;
            return true;
        }
        return false;
    }

    bool getServerData(const std::string &name, RegServerKey &val) {
        if (uniqueServers.find(name) != uniqueServers.end()) {
            val = uniqueServers[name];
            return true;
        }
        return false;
    }

    void insert(const std::string &name, RegServerKey &val) {
        uniqueServers.insert_or_assign(name, val);
        serialize();
    }

    void remove(const std::string &name) {
        uniqueServers.erase(name);
    }

    ServerReg() = default;
    ~ServerReg() = default;
};

ServerReg regServer;

std::string getMacAddress() {
    std::string name;
    regServer.getServerDataFirst(name);
    return name;
}

// UUIDs
static BLEUUID serviceUUID("abcd");
static BLEUUID publicCharUUID("1234");

NimBLEAdvertisedDevice *advDevice = nullptr;
std::string uniqueUUID;
QueueHandle_t outgoingQueue;

CommandManager commandManager;

void connectToServer();

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

SecureConnection con;
QueueHandle_t responseQueue;

class AdvertisedDeviceCallbacks : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice *advertisedDevice) override {
        logColor(LColor::Green, F("Found device: %s (%s)"), advertisedDevice->toString().c_str(), advertisedDevice->getName().c_str());
        if (advertisedDevice->haveServiceUUID()) {
            logColor(LColor::Green, F("Service device: %d === %s"), (int)advertisedDevice->isAdvertisingService(serviceUUID), serviceUUID.toString().c_str());
        } else {
            logColor(LColor::Green, F("No service"));
        }
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
NimBLEClientCallbacks *clientCbk = nullptr;
std::string servMac;

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


//////////////
const std::string BEGIN_SEND = "begin_transaction"; 
const std::string END_SEND = "end_transaction";
std::string baptsBuffer;\
bool partParsing = false;
const std::string ComNeedNext = "NEXT";

void onNotify(NimBLERemoteCharacteristic *pBLERemoteCharacteristic, uint8_t *pData, size_t length, bool isNotify) {
    Log.notice("onNotify NimBLERemoteCharacteristic");
    std::string data((char *)pData, length);
    logColor(LColor::Yellow, F("Notification: %s"), data.c_str());

    if (data == ComNeedNext)
    {
        BleLock::setWaiter(servMac, true);
        logColor(LColor::Yellow, F("Notification: Need Next Part"));
        return;
    }


    if (data == BEGIN_SEND)
    {
        baptsBuffer.clear();
        partParsing = true;
        logColor(LColor::Yellow, F("Notification: PARTS begin"));
        pBLERemoteCharacteristic->writeValue (ComNeedNext);
        return;
    }
    if (partParsing)
    {
        if (data == END_SEND)
        {
            data = baptsBuffer;
            baptsBuffer.clear();
            partParsing = false;
            logColor(LColor::Yellow, F("Notification: PARTS STOP"));
        }
        else
        {
            baptsBuffer += data;
            pBLERemoteCharacteristic->writeValue (ComNeedNext);
            return;
        }
    }

    std::string *addr = new std::string(servMac);
    std::tuple<std::string *, std::string *> *messageAndMac = new std::tuple<std::string *, std::string *>(new std::string(data), addr);

    if (xQueueSend(key.jsonParsingQueue, &messageAndMac, portMAX_DELAY) != pdPASS) {
        logColor(LColor::Yellow, F("Notification NOT stored"));
    } else {
        logColor(LColor::Yellow, F("Notification stored"));
    }
}

NimBLERemoteCharacteristic *pUniqueChar = nullptr;
static bool isNeedSubscribe = false;
NimBLERemoteCharacteristic *pUniqueCharExt = nullptr;

[[noreturn]] void connectionLoopTask(void *parameter) {
    while (true) {
        if (pClient != nullptr && isNeedSubscribe) {
            NimBLERemoteService *pService = pClient->getService(serviceUUID);

            if (pService) {
                NimBLERemoteCharacteristic *pUniqueChar = pService->getCharacteristic(uniqueUUID);
                if (pUniqueChar) {
                    logColor(LColor::LightCyan, F("Try to subscribe to characteristic: %s"), uniqueUUID.c_str());
                    bool success = pUniqueChar->subscribe(true, onNotify);
                    if (success) {
                        logColor(LColor::Green, F("Subscribed to unique characteristic %s"), uniqueUUID.c_str());
                        isNeedSubscribe = false;
                        pUniqueCharExt = pUniqueChar;
                    } else {
                        logColor(LColor::Red, F("Failed to subscribe to unique characteristic %s, reconnecting..."), uniqueUUID.c_str());
                        pClient->disconnect();
                    }
                } else {
                    logColor(LColor::Red, F("Unique characteristic %s not found, reconnecting..."), uniqueUUID.c_str());
                    pClient->disconnect();
                }
            } else {
                logColor(LColor::Red, F("Service %s not found, reconnecting..."), serviceUUID.toString().c_str());
                pClient->disconnect();
            }
        }
        vTaskDelay(200 / portTICK_PERIOD_MS);
    }
}

[[noreturn]] void sendOpenTask(void *parameter) {
    while (true) {
        if (key.secureConnection.aesKeys.size() > 0) {
            OpenRequest *msg = new OpenRequest;
            msg->processRequest(&key);
        }
        vTaskDelay(10000 / portTICK_PERIOD_MS);
    }
}

void connectToServer() {
    logColor(LColor::Green, F("Attempting to connect to server"));
    if (pClient == nullptr) {
        pClient = NimBLEDevice::createClient();
    }

    if (clientCbk == nullptr) {
        clientCbk = new ClientCallbacks();
    }
    pClient->setClientCallbacks(clientCbk, false);

    if (pClient->connect(advDevice)) {
        logColor(LColor::Green, F("Connected to server"));

        NimBLERemoteService *pService = pClient->getService(serviceUUID);
        if (pService) {
            NimBLERemoteCharacteristic *pPublicChar = pService->getCharacteristic(publicCharUUID);
            if (pPublicChar) 
            {
                std::string data = pPublicChar->readValue();
                uniqueUUID = data;

                std::string mac = advDevice->getAddress().toString();
                RegServerKey reg;
                reg.characteristicUUID = uniqueUUID;
                reg.macAdr = mac;
                servMac = mac;

                regServer.insert(mac, reg);
                logColor(LColor::Yellow, F("Registered server: MAC - %s, UUID - %s"), mac.c_str(), uniqueUUID.c_str());


                pUniqueChar = pService->getCharacteristic(uniqueUUID);
                if (pUniqueChar) {
                    logColor(LColor::LightCyan, F("Attempting to subscribe to characteristic: %s"), uniqueUUID.c_str());
                    bool success = pUniqueChar->subscribe(true, onNotify);
                    if (success) {
                        logColor(LColor::Green, F("Subscribed to unique characteristic %s"), uniqueUUID.c_str());
                        isNeedSubscribe = false;
                        pUniqueCharExt = pUniqueChar;
                    } else {
                        logColor(LColor::Red, F("Subscription to characteristic %s failed, reconnecting..."), uniqueUUID.c_str());
                        pClient->disconnect();
                    }
                } else {
                    logColor(LColor::Red, F("Characteristic %s not found, reconnecting..."), uniqueUUID.c_str());
                    pClient->disconnect();
                }
            } else {
                logColor(LColor::Red, F("Public characteristic %s not found, reconnecting..."), publicCharUUID.toString().c_str());
                pClient->disconnect();
            }
        } else {
            logColor(LColor::Red, F("Service %s not found, reconnecting..."), serviceUUID.toString().c_str());
            pClient->disconnect();
        }
    } else {
        logColor(LColor::Red, F("Connection to server failed"));
    }
}

volatile bool isOkRes = false; 
NimBLEScan *pScan = nullptr;
volatile bool noMore = false;
std::unordered_map<std::string, KeyStatusType> Locks;

std::unordered_map<std::string, KeyStatusType> LocksLastCall;

[[noreturn]] void scenrioTempTask(void *parameters) {
    while (true) {
/*        if (isOkRes && !noMore) {
            logColor (LColor::LightRed, F("Strtt connect"));
            OpenRequest *msg = new OpenRequest;
            msg->destinationAddress = servMac;
            msg->sourceAddress = key.getMacAddress();
            xQueueSend(outgoingQueue, &msg, portMAX_DELAY);
            noMore = true;
        }

                                ReqRegKey *req =  new ReqRegKey;
                        req->destinationAddress= servMac;
                        req->sourceAddress = getMacSelf();
                        xQueueSend (outgoingQueue, &req, portMAX_DELAY);

        */
        for (auto it = Locks.begin (); it != Locks.end(); it++)
        {
            switch (it->second)
            {
                case KeyStatusType::statusNone:
                {
                    auto req = new HelloRequest;
                    req->sourceAddress = getMacAddress();
                    req->destinationAddress = it->first;
                    req->status = false;
                    req->key = "";
                    it->second = KeyStatusType::statusWaitForAnswer;
                    LocksLastCall[it->first] = KeyStatusType::statusNone; 
                    xQueueSend (outgoingQueue, &req, portMAX_DELAY);
                    break;
                }
                case KeyStatusType::statusPublickKeyExist:
                {
                    auto req = new HelloRequest;
                    req->sourceAddress = getMacAddress();
                    req->destinationAddress = it->first;
                    req->status = true;
                    req->key = key.secureConnection.generatePublicKeyHash (key.secureConnection.keys[it->first].first,16);
                    it->second = KeyStatusType::statusWaitForAnswer;
                    LocksLastCall[it->first] = KeyStatusType::statusPublickKeyExist; 
                    xQueueSend (outgoingQueue, &req, portMAX_DELAY);
                    break;
                }
                case KeyStatusType::statusSessionKeyCreated:
                {
                    ReqRegKey *req =  new ReqRegKey;
                    req->sourceAddress = getMacAddress();
                    req->destinationAddress = it->first;
                    key.secureConnection.generateAESKey (it->first);
                    req->key = key.secureConnection.encryptMessageRSA(key.secureConnection.aesKeys[it->first],it->first);
                    it->second = KeyStatusType::statusWaitForAnswer;
                    LocksLastCall[it->first] = KeyStatusType::statusSessionKeyCreated; 
                    xQueueSend (outgoingQueue, &req, portMAX_DELAY);
                    break;
                }
                case KeyStatusType::statusOpenCommand:
                {
                    OpenRequest *req = new OpenRequest;
                    req->sourceAddress = getMacAddress();
                    req->destinationAddress = it->first;
                    it->second = KeyStatusType::statusWaitForAnswer;
                    LocksLastCall[it->first] = KeyStatusType::statusOpenCommand; 
                    xQueueSend (outgoingQueue, &req, portMAX_DELAY);
                    break;
                }

                default:
                    break;
            }
        }
        vTaskDelay(5000 / portTICK_PERIOD_MS);
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

    responseQueue = key.responseQueue;
    outgoingQueue = key.outgoingQueue;

    //xTaskCreate(connectionLoopTask, "connectionLoopTask", 8192, nullptr, 1, nullptr);
    xTaskCreate(sendOpenTask, "sendOpenTask", 8192, nullptr, 1, nullptr);


    bool registerResOk = []() {
        MessageBase::registerConstructor(MessageType::resOk, []() -> MessageBase * { return new ResOk(); });
        return true;
    }();
    bool registerReqRegKey = []() {
        MessageBase::registerConstructor(MessageType::reqRegKey, []() -> MessageBase * { return new ReqRegKey(); });
        return true;
    }();

    bool registerResKey = []() {
        MessageBase::registerConstructor(MessageType::resKey, []() -> MessageBase * { return new ResKey(); });
        return true;
    }();

    bool registerOpenReq = []() {
        MessageBase::registerConstructor(MessageType::OpenRequest, []() -> MessageBase * { return new OpenRequest(); });
        return true;
    }();
    bool registerOpenCmd = []() {
        MessageBase::registerConstructor(MessageType::OpenCommand, []() -> MessageBase * { return new OpenCommand(); });
        return true;
    }();
    bool registerSecurituCheck = []() {
        MessageBase::registerConstructor(MessageType::SecurityCheckRequestest, []() -> MessageBase * { return new SecurityCheckRequestest(); });
        return true;
    }();
    bool registerHelloRequest = []() {
        MessageBase::registerConstructor(MessageType::HelloRequest, []() -> MessageBase * { return new HelloRequest(); });
        return true;
    }();
    bool registerReceivePublic = []() {
        MessageBase::registerConstructor(MessageType::ReceivePublic, []() -> MessageBase * { return new ReceivePublic(); });
        return true;
    }();


    pScan = NimBLEDevice::getScan();
    

    commandManager.registerHandler("connectToServer", []() {
        connectToServer();
    });

    commandManager.registerHandler("rescanToServer", []() {
        logColor(LColor::Green, F("Handled rescanToServer event"));

        pScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks());
        pScan->setActiveScan(true);
        pScan->start(30, false);
    });

    commandManager.registerHandler("onConnect", []() {
        logColor(LColor::Green, F("Handled onConnect event"));
        if (pUniqueCharExt!=nullptr)
        {
            Locks[servMac] = KeyStatusType::statusNone;
            auto trio = key.secureConnection.keys.find(servMac);
            if (trio != key.secureConnection.keys.end())
                Locks[servMac] = KeyStatusType::statusPublickKeyExist;
        }
    });

    commandManager.registerHandler("onDisconnect", []() {
        logColor(LColor::Yellow, F("Handled onDisconnect event, attempting to reconnect..."));
        commandManager.sendCommand("rescanToServer");
    });

    commandManager.startProcessing();

    xTaskCreate(scenrioTempTask, "scenrioTempTask", 8192, nullptr, 1, nullptr);

    pScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks());
    pScan->setActiveScan(true);
    pScan->start(30, false);
}

void loop() {
    static unsigned long lastTempCheck = 0;
    if (millis() - lastTempCheck >= 10000) {
        float temperature = TemperatureMonitor::getTemperature();

        char temperatureStr[10];
        dtostrf(temperature, 6, 2, temperatureStr);

        Log.notice(F("CPU Temperature: %s В°C"), temperatureStr);

        size_t freeHeap = esp_get_free_heap_size();
        logColor(LColor::Yellow, F("Free heap memory: %d bytes"), freeHeap);
        lastTempCheck = millis();
    }
}
