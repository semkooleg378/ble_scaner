
#include <BleLockAndKey.h>
#include "ReqRes.h"

#include "TemperatureMonitor.h"
#include <vector>

BleLockClient * key = nullptr;//("BleKey");

std::unordered_map<std::string, KeyStatusType> LocksLastCall;

[[noreturn]] void scenrioTempTask(void *parameters) {
    while (true) {
        for (auto it = BleLockClient::Locks.begin (); it != BleLockClient::Locks.end(); it++)
        {
            switch (it->second)
            {
                case KeyStatusType::statusNone:
                {
                    auto req = new HelloRequest;
                    req->sourceAddress = key->getMacAddress();
                    req->destinationAddress = it->first;
                    req->status = false;
                    req->key = "";
                    it->second = KeyStatusType::statusWaitForAnswer;
                    LocksLastCall[it->first] = KeyStatusType::statusNone; 
                    xQueueSend (key->GetOutgoingQueue(), &req, portMAX_DELAY);
                    break;
                }
                case KeyStatusType::statusPublickKeyExist:
                {
                    auto req = new HelloRequest;
                    req->sourceAddress = key->getMacAddress();
                    req->destinationAddress = it->first;
                    req->status = true;
                    req->key = key->secureConnection.generatePublicKeyHash (key->secureConnection.keys[it->first].first,16);
                    it->second = KeyStatusType::statusWaitForAnswer;
                    LocksLastCall[it->first] = KeyStatusType::statusPublickKeyExist; 
                    xQueueSend (key->GetOutgoingQueue(), &req, portMAX_DELAY);
                    break;
                }
                case KeyStatusType::statusSessionKeyCreated:
                {
                    ReqRegKey *req =  new ReqRegKey;
                    req->sourceAddress = key->getMacAddress();
                    req->destinationAddress = it->first;
                    key->secureConnection.generateAESKey (it->first);
                    req->key = key->secureConnection.encryptMessageRSA(key->secureConnection.aesKeys[it->first],it->first);
                    it->second = KeyStatusType::statusWaitForAnswer;
                    LocksLastCall[it->first] = KeyStatusType::statusSessionKeyCreated; 
                    xQueueSend (key->GetOutgoingQueue(), &req, portMAX_DELAY);
                    break;
                }
                case KeyStatusType::statusOpenCommand:
                {
                    OpenRequest *req = new OpenRequest;
                    req->sourceAddress = key->getMacAddress();
                    req->destinationAddress = it->first;
                    it->second = KeyStatusType::statusWaitForAnswer;
                    LocksLastCall[it->first] = KeyStatusType::statusOpenCommand; 
                    xQueueSend (key->GetOutgoingQueue(), &req, portMAX_DELAY);
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
    IntSAtringMap::insert ((MessageType)MessageTypeReg::resOk, "resOk");
    IntSAtringMap::insert ((MessageType)MessageTypeReg::reqRegKey, "reqRegKey");
    IntSAtringMap::insert ((MessageType)MessageTypeReg::OpenRequest, "OpenRequest");
    IntSAtringMap::insert ((MessageType)MessageTypeReg::SecurityCheckRequestest, "SecurityCheckRequestest");
    IntSAtringMap::insert ((MessageType)MessageTypeReg::OpenCommand, "OpenCommand");
    IntSAtringMap::insert ((MessageType)MessageTypeReg::resKey, "resKey");
    IntSAtringMap::insert ((MessageType)MessageTypeReg::HelloRequest, "HelloRequest");
    IntSAtringMap::insert ((MessageType)MessageTypeReg::ReceivePublic, "ReceivePublic");

    key = (BleLockClient*)createAndInitLock(false, "BleKey");
    BleLockClient::SetCurrentClient(key);
    delay(10000);
    logColor (LColor::Green, F("Srarted"));

    bool registerResOk = []() {
        MessageBase::registerConstructor((MessageType)MessageTypeReg::resOk, []() -> MessageBase * { return new ResOk(); });
        return true;
    }();
    bool registerReqRegKey = []() {
        MessageBase::registerConstructor((MessageType)MessageTypeReg::reqRegKey, []() -> MessageBase * { return new ReqRegKey(); });
        return true;
    }();

    bool registerResKey = []() {
        MessageBase::registerConstructor((MessageType)MessageTypeReg::resKey, []() -> MessageBase * { return new ResKey(); });
        return true;
    }();

    bool registerOpenReq = []() {
        MessageBase::registerConstructor((MessageType)MessageTypeReg::OpenRequest, []() -> MessageBase * { return new OpenRequest(); });
        return true;
    }();
    bool registerOpenCmd = []() {
        MessageBase::registerConstructor((MessageType)MessageTypeReg::OpenCommand, []() -> MessageBase * { return new OpenCommand(); });
        return true;
    }();
    bool registerSecurituCheck = []() {
        MessageBase::registerConstructor((MessageType)MessageTypeReg::SecurityCheckRequestest, []() -> MessageBase * { return new SecurityCheckRequestest(); });
        return true;
    }();
    bool registerHelloRequest = []() {
        MessageBase::registerConstructor((MessageType)MessageTypeReg::HelloRequest, []() -> MessageBase * { return new HelloRequest(); });
        return true;
    }();
    bool registerReceivePublic = []() {
        MessageBase::registerConstructor((MessageType)MessageTypeReg::ReceivePublic, []() -> MessageBase * { return new ReceivePublic(); });
        return true;
    }();

    xTaskCreate(scenrioTempTask, "scenrioTempTask", 8192, nullptr, 1, nullptr);
    //TemperatureMonitor::begin ();
    BleLockClient::StartScan();
}

void loop() {
    static unsigned long lastTempCheck = 0;
    if (millis() - lastTempCheck >= 10000) {
        float temperature = TemperatureMonitor::getTemperature();

        char temperatureStr[10];
        dtostrf(temperature, 6, 2, temperatureStr);

        logColor(LColor::Yellow,F("CPU Temperature: %s В°C"), temperatureStr);

        size_t freeHeap = esp_get_free_heap_size();
        logColor(LColor::Yellow, F("Free heap memory: %d bytes"), freeHeap);
        lastTempCheck = millis();
    }
}
