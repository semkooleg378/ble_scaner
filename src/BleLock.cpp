#include "BleLock.h"
#include "ReqRes.h"

// Callbacks Implementation
void printCharacteristics(NimBLEService *pService) {
    Log.notice("%s\n", "Listing characteristics:");

    std::vector<NimBLECharacteristic *> characteristics = pService->getCharacteristics();
    for (auto &characteristic: characteristics) {
        Log.notice("%s", "Characteristic UUID: ");
        Log.notice("%s\n", characteristic->getUUID().toString().c_str());

        Log.notice("%s", "Properties: ");
        uint32_t properties = characteristic->getProperties();
        if (properties & NIMBLE_PROPERTY::READ) {
            Log.notice("%s", "READ ");
        }
        if (properties & NIMBLE_PROPERTY::WRITE) {
            Log.notice("%s", "WRITE ");
        }
        if (properties & NIMBLE_PROPERTY::NOTIFY) {
            Log.notice("%s", "NOTIFY ");
        }
        if (properties & NIMBLE_PROPERTY::INDICATE) {
            Log.notice("%s", "INDICATE ");
        }
        Log.notice("");
    }
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
void logColor(LColor color, const __FlashStringHelper *format, ...) ;

MessageBase *BleLock::request(MessageBase *requestMessage, const std::string &destAddr, uint32_t timeout) const {
    requestMessage->sourceAddress = macAddress; // Use the stored MAC address
    requestMessage->destinationAddress = destAddr;
    requestMessage->requestUUID = requestMessage->generateUUID(); // Generate a new UUID for the request

    if (xQueueSend(outgoingQueue, &requestMessage, portMAX_DELAY) != pdPASS) {
        Log.error(F("Failed to send request to the outgoing queue"));
        return nullptr;
    }

    uint32_t startTime = xTaskGetTickCount();
    std::string *receivedMessage;

    while (true) {
        uint32_t elapsed = xTaskGetTickCount() - startTime;
        if (elapsed >= pdMS_TO_TICKS(timeout)) {
            // Timeout reached
            return nullptr;
        }

        // Peek at the queue to see if there is a message
        if (xQueuePeek(responseQueue, &receivedMessage, pdMS_TO_TICKS(timeout) - elapsed) == pdTRUE) {
            // Create an instance of MessageBase from the received message
            MessageBase *instance = MessageBase::createInstance(*receivedMessage);

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


BleLock::BleLock(std::string keyName)
        : lockName(std::move(keyName)), pServer(nullptr), pService(nullptr), pPublicCharacteristic(nullptr),
          autoincrement(0) {
    memoryFilename = "/ble_key_memory.json";
    Log.verbose(F("xQueueCreate "));
    //characteristicCreationQueue = xQueueCreate(10, sizeof(CreateCharacteristicCmd *)); // Queue to hold char* pointers
    outgoingQueue = xQueueCreate(10, sizeof(MessageBase *));
    responseQueue = xQueueCreate(10, sizeof(std::string *));
    Log.verbose(F("initializeMutex "));
    initializeMutex();
    Log.verbose(F("done "));
}

void BleLock::setup() {
    Log.verbose(F("Starting BLE setup..."));

    BLEDevice::init(lockName);
    Log.verbose(F("BLEDevice::init completed"));

    // Get the MAC address and store it
    macAddress = BLEDevice::getAddress().toString();
    Log.verbose(F("Device MAC address: %s"), macAddress.c_str());

    // Create the JSON parsing queue
    jsonParsingQueue = xQueueCreate(10, sizeof(std::string *));
    if (jsonParsingQueue == nullptr) {
        Log.error(F("Failed to create JSON parsing queue"));
        return;
    }

    // Create the JSON parsing task
    xTaskCreate(jsonParsingTask, "JsonParsingTask", 8192, this, 1, nullptr);
    Log.verbose(F("JsonParsingTask created"));
    
    xTaskCreate(outgoingMessageTask, "outgoingMessageTask", 8192, this, 1, nullptr);
    Log.verbose(F("outgoingMessageTask created"));

//    loadCharacteristicsFromMemory();
}


QueueHandle_t BleLock::getOutgoingQueueHandle() const {
    return outgoingQueue;
}

void BleLock::initializeMutex() {
    bleMutex = xSemaphoreCreateMutex();
    if (bleMutex == nullptr) {
        Log.error(F("Failed to create the mutex"));
    }
}

/*std::string BleLock::generateUUID() {
    char uuid[37];
    snprintf(uuid, sizeof(uuid),
             "%08x-%04x-%04x-%04x-%012x",
             esp_random(),
             (autoincrement++ & 0xFFFF),
             (esp_random() & 0x0FFF) | 0x4000,
             (esp_random() & 0x3FFF) | 0x8000,
             esp_random());
    return {uuid};
}
*/

[[noreturn]] void BleLock::outgoingMessageTask(void *pvParameter) {
    auto *bleLock = static_cast<BleLock *>(pvParameter);
    MessageBase *responseMessage;

    Log.verbose(F("Starting outgoingMessageTask..."));
    while (true) {
        Log.verbose(F("outgoingMessageTask: Waiting to receive message from queue..."));

        if (xQueueReceive(bleLock->outgoingQueue, &responseMessage, portMAX_DELAY) == pdTRUE) {
            Log.verbose(F("Message received from queue"));

            Log.verbose(F("BleLock::responseMessageTask msg: %s %s"), responseMessage->destinationAddress.c_str(),
                        ToString(responseMessage->type));

            // Lock the mutex for advertising and characteristic operations
            Log.verbose(F("outgoingMessageTask: Waiting for Mutex"));
            xSemaphoreTake(bleLock->bleMutex, portMAX_DELAY);
            Log.verbose(F("outgoingMessageTask: Mutex lock"));

            //auto it = bleLock->uniqueCharacteristics.find(responseMessage->destinationAddress);
            extern NimBLERemoteCharacteristic *pUniqueChar;
            if (1)//it != bleLock->uniqueCharacteristics.end())
            {
                Log.verbose(F("Destination address found in uniqueCharacteristics %s"),
                            responseMessage->destinationAddress.c_str());

                NimBLERemoteCharacteristic *characteristic = pUniqueChar;
                std::string serializedMessage = responseMessage->serialize();
                Log.verbose(F("Serialized message: %s"), serializedMessage.c_str());

                characteristic->writeValue(serializedMessage);
                Log.verbose(F("Characteristic value set"));

                //characteristic->notify();
                Log.verbose(F("Characteristic notified"));
            } else {
                Log.error(F("Destination address not found in uniqueCharacteristics"));
            }

            delete responseMessage;
            Log.verbose(F("Response message deleted"));

            //bleLock->resumeAdvertising();
            Log.verbose(F("Advertising resumed"));

            // Unlock the mutex for advertising and characteristic operations
            xSemaphoreGive(bleLock->bleMutex);
            Log.verbose(F("outgoingMessageTask: Mutex unlock"));
        } else {
            Log.error(F("Failed to receive message from queue"));
        }
    }
}

[[noreturn]] void BleLock::jsonParsingTask(void *pvParameter) {
    auto *bleLock = static_cast<BleLock *>(pvParameter);
    std::string *receivedMessageStr;

    while (true) {
        Log.verbose(F("jsonParsingTask: Waiting to receive message from queue..."));

        if (xQueueReceive(bleLock->jsonParsingQueue, &receivedMessageStr, portMAX_DELAY) == pdTRUE) {
            Log.verbose(F("jsonParsingTask: Received message: %s"), receivedMessageStr->c_str());

            try {
                auto msg = MessageBase::createInstance(*receivedMessageStr);
                if (msg) {
                    Log.verbose(F("Received request from: %s with type: %s"), msg->sourceAddress.c_str(),
                                ToString(msg->type));

                    MessageBase *responseMessage = msg->processRequest(bleLock);
                    delete msg;

                    if (responseMessage) {
                        Log.verbose(F("Sending response message to outgoing queue"));
                        responseMessage->destinationAddress = msg->sourceAddress;
                        responseMessage->sourceAddress = msg->destinationAddress;
                        responseMessage->requestUUID = msg->requestUUID;
                        if (xQueueSend(bleLock->outgoingQueue, &responseMessage, portMAX_DELAY) != pdPASS) {
                            Log.error(F("Failed to send response message to outgoing queue"));
                            delete responseMessage;
                        }
                    } else {
                        auto responseMessageStr = new std::string(*receivedMessageStr);
                        Log.verbose(F("Sending response message string to response queue"));
                        if (xQueueSend(bleLock->responseQueue, &responseMessageStr, portMAX_DELAY) != pdPASS) {
                            Log.error(F("Failed to send response message string to response queue"));
                            delete responseMessageStr;
                        }
                    }
                } else {
                    Log.error(F("Failed to create message instance"));
                }
            } catch (const json::parse_error &e) {
                Log.error(F("JSON parse error: %s"), e.what());
            } catch (const std::exception &e) {
                Log.error(F("Exception occurred: %s"), e.what());
            }

            // Free the allocated memory for the received message
            delete receivedMessageStr;
        }
    }
}

