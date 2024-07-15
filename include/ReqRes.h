#include "MessageBase.h"
#include "BleLock.h"

#define MessageMaxDelay 30000

extern volatile bool isOkRes;

class ResOk : public MessageBase {
public:
    bool status{};

    ResOk() {
        type = MessageType::resOk;
        requestUUID = generateUUID();
    }

    explicit ResOk(bool status) : status(status) {
        type = MessageType::resOk;
    }

protected:
    void serializeExtraFields(json &doc) override {
        doc["status"] = status;
        Serial.printf("Serialized status: %d\n", status);
    }

    void deserializeExtraFields(const json &doc) override {
        status = doc["status"];
        Serial.printf("Deserialized status: %d\n", status);
    }
    MessageBase *processRequest(void *context) override {
        return nullptr;
    }
};


class ResKey : public MessageBase {
public:
    bool status{};
    std::string key{};

    ResKey() {
        type = MessageType::resKey;
        requestUUID = generateUUID();
    }

    explicit ResKey(bool status, std::string newKey) : status(status), key(newKey) {
        type = MessageType::resKey;
    }

protected:
    void serializeExtraFields(json &doc) override {
        doc["status"] = status;
        doc["key"] = key;
        Serial.printf("Serialized status: %d  key:%s\n", status, key.c_str());
    }

    void deserializeExtraFields(const json &doc) override {
        status = doc["status"];
        key = doc["key"];
        Serial.printf("Deserialized status: %d  key:%s\n", status, key.c_str());
    }
    MessageBase *processRequest(void *context) override {
        auto lock = static_cast<BleLock *>(context);
        isOkRes = true;
        lock->secureConnection.SetAESKey(sourceAddress,key);         
        return nullptr;
    }
};



class ReqRegKey : public MessageBase {
public:
    std::string key;

    ReqRegKey() {
        type = MessageType::reqRegKey;
        requestUUID = generateUUID();
    }

#if 0
    MessageBase *processRequest(void *context) override {
        auto lock = static_cast<BleLock *>(context);
        if (xSemaphoreTake(lock->bleMutex, portMAX_DELAY) == pdTRUE) {
            //lock->awaitingKeys.insert(key);
            xSemaphoreGive(lock->bleMutex);
        }
        auto res = new ResKey();
        res->destinationAddress = key;
        res->sourceAddress = key;
        res->status = 0;
        res->key =  key;
        return res;
    }
    #endif

protected:
    void serializeExtraFields(json &doc) override {
        doc["key"] = key;
        Serial.printf("Serialized key: %s\n", key.c_str());
    }

    void deserializeExtraFields(const json &doc) override {
        key = doc["key"];
        Serial.printf("Deserialized key: %s\n", key.c_str());
    }
};

class OpenCommand : public MessageBase {
public:
    std::string randomField;

    OpenCommand() {
        type = MessageType::OpenCommand;
        requestUUID = generateUUID();
    }

    void setRandomField(std::string randomFieldVal)
    {
        randomField = randomFieldVal;
    }
    #if 0
    MessageBase *processRequest(void *context) override {
        auto lock = static_cast<BleLock *>(context);
        if (xSemaphoreTake(lock->bleMutex, portMAX_DELAY) == pdTRUE) {
            //lock->awaitingKeys.insert(key);
            xSemaphoreGive(lock->bleMutex);
        }
        auto res = new ResOk();
        res->destinationAddress = sourceAddress;
        res->sourceAddress = destinationAddress;
        res->status = true;
        return res;
    }
    #endif
    std::string getEncryptedCommand ()
    {
        return randomField;
    }

protected:
    void serializeExtraFields(json &doc) override {
        doc["randomField"] = randomField;
        Log.notice("Serialized randomField: %s\n", randomField.c_str());
    }

    void deserializeExtraFields(const json &doc) override {
        randomField = doc["randomField"];
        Log.notice("Deserialized randomField: %s\n", randomField.c_str());
    }
};

class SecurityCheckRequestest : public MessageBase {
public:
    std::string randomField;

    SecurityCheckRequestest() {
        type = MessageType::SecurityCheckRequestest;
        requestUUID = generateUUID();
    }

    void setRandomField(std::string randomFieldVal)
    {
        randomField = randomFieldVal;
    }
    MessageBase *processRequest(void *context) override {
        auto lock = static_cast<BleLock *>(context);
        //if (xSemaphoreTake(lock->bleMutex, portMAX_DELAY) == pdTRUE) {
        //    lock->awaitingKeys.insert(key);
        //    xSemaphoreGive(lock->bleMutex);
        //}
        bool result =- false;
        std::string resultStr = lock->secureConnection.encryptMessageAES(randomField,sourceAddress);
        //result = (lock->temporaryField == resultStr);
        auto res = new OpenCommand();
        res->destinationAddress = sourceAddress;
        res->sourceAddress = destinationAddress;
        res->setRandomField (resultStr);
        res->requestUUID = requestUUID;
        return res;
    }

    std::string getEncryptedCommand (BleLock *lock)
    {
        return lock->secureConnection.encryptMessageAES(randomField,"UUID");;
    }

protected:
    void serializeExtraFields(json &doc) override {
        doc["randomField"] = randomField;
        Log.notice("Serialized randomField: %s\n", randomField.c_str());
    }

    void deserializeExtraFields(const json &doc) override {
        randomField = doc["randomField"];
        Log.notice("Deserialized randomField: %s\n", randomField.c_str());
    }
};



class OpenRequest : public MessageBase {
public:
    std::string key;
    std::string randomField;

    OpenRequest() {
        type = MessageType::OpenRequest;
        requestUUID = generateUUID();
    }

    void setRandomField(std::string randomFieldVal)
    {
        randomField = randomFieldVal;
    }

#if 0
    MessageBase *processRequest(void *context) override {
        auto lock = static_cast<BleLock *>(context);

        std::string randomField = lock->secureConnection.generateRandomField();

        // Создаем запрос для проверки безопасности
        SecurityCheckRequestest* securityCheckRequest = new SecurityCheckRequestest();
        securityCheckRequest->sourceAddress = lock->getMacAddress();
        securityCheckRequest->destinationAddress = sourceAddress;
        //securityCheckRequest->type = MessageType::SecurityCheck;
        securityCheckRequest->setRandomField(randomField);

        // Отправляем запрос на проверку безопасности и ждем ответ
        MessageBase* securityCheckResponse = lock->request(securityCheckRequest, sourceAddress, MessageMaxDelay);
        delete securityCheckRequest;

        if (securityCheckResponse && securityCheckResponse->type == MessageType::OpenCommand) 
        {
            // Расшифровываем команду открытия и проверяем рандомное поле
            std::string decryptedCommand = lock->secureConnection.decryptMessageAES(((OpenCommand*)securityCheckResponse)->getEncryptedCommand(), sourceAddress);
            if (decryptedCommand == randomField) {
                // Отправляем ответ об успешном открытии
                ResOk* successResponse = new ResOk();
                successResponse->sourceAddress = lock->getMacAddress();
                successResponse->destinationAddress = sourceAddress;
                //successResponse->type = MessageType::ResOk;

                lock->request(successResponse, sourceAddress, MessageMaxDelay/* таймаут */);
                //delete successResponse;
                delete securityCheckResponse;
                //delete request;

                Log.verbose(F("Замок открыт успешно"));
                return successResponse; // Успешное завершение
            } else {
                Log.error(F("Ошибка проверки безопасности"));
            }
        } else {
            Log.error(F("Не удалось получить ответ на проверку безопасности"));
        }

        if (securityCheckResponse) delete securityCheckResponse;

        return nullptr;
    }
    #endif

protected:
    void serializeExtraFields(json &doc) override {
        doc["key"] = key;
        doc["randomField"] = randomField;
        Log.notice("Serialized OpenRequest: %s\n", randomField.c_str());
    }

    void deserializeExtraFields(const json &doc) override {
        key = doc["key"];
        randomField = doc["randomField"];
        Log.notice("Deserialized OpenRequest: %s\n", randomField.c_str());
    }
};
