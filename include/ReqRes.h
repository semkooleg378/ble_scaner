#include "MessageBase.h"
#include "BleLock.h"

#define MessageMaxDelay 30000

class ResOk : public MessageBase {
public:
    bool status{};

    ResOk() {
        type = MessageType::ResOk;
    }

    explicit ResOk(bool status) : status(status) {
        type = MessageType::ResOk;
    }

protected:
    void serializeExtraFields(json &doc) override {
        doc["status"] = status;
        Log.notice("Serialized status: %d\n", status);
    }

    void deserializeExtraFields(const json &doc) override {
        status = doc["status"];
        Log.notice("Deserialized status: %d\n", status);
    }
};



class ReqRegKey : public MessageBase {
public:
    std::string key;

    ReqRegKey() {
        type = MessageType::reqRegKey;
    }

    MessageBase *processRequest(void *context) override {
        auto lock = static_cast<BleLock *>(context);
        if (xSemaphoreTake(lock->bleMutex, portMAX_DELAY) == pdTRUE) {
            //lock->awaitingKeys.insert(key);
            xSemaphoreGive(lock->bleMutex);
        }
        auto res = new ResOk();
        res->destinationAddress = key;
        res->sourceAddress = key;
        return res;
    }

protected:
    void serializeExtraFields(json &doc) override {
        doc["key"] = key;
        Log.notice("Serialized key: %s\n", key.c_str());
    }

    void deserializeExtraFields(const json &doc) override {
        key = doc["key"];
        Log.notice("Deserialized key: %s\n", key.c_str());
    }
};

class OpenCommand : public MessageBase {
public:
    std::string key;
    std::string randomField;

    OpenCommand() {
        type = MessageType::OpenCommand;
    }

    void setRandomField(std::string randomFieldVal)
    {
        randomField = randomFieldVal;
    }
    MessageBase *processRequest(void *context) override {
        auto lock = static_cast<BleLock *>(context);
        if (xSemaphoreTake(lock->bleMutex, portMAX_DELAY) == pdTRUE) {
            //lock->awaitingKeys.insert(key);
            xSemaphoreGive(lock->bleMutex);
        }
        auto res = new ResOk();
        res->destinationAddress = key;
        res->sourceAddress = key;
        return res;
    }

    std::string getEncryptedCommand ()
    {
        return randomField;
    }

protected:
    void serializeExtraFields(json &doc) override {
        doc["key"] = key;
        Log.notice("Serialized key: %s\n", key.c_str());
    }

    void deserializeExtraFields(const json &doc) override {
        key = doc["key"];
        Log.notice("Deserialized key: %s\n", key.c_str());
    }
};

class SecurityCheckRequestest : public MessageBase {
public:
    std::string key;
    std::string randomField;

    SecurityCheckRequestest() {
        type = MessageType::SecurityCheckRequestest;
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
        std::string resultStr = lock->secureConnection.encryptMessageAES(randomField,"UUID");
        //result = (lock->temporaryField == resultStr);
        auto res = new OpenCommand();
        res->destinationAddress = key;
        res->sourceAddress = key;
        res->setRandomField (resultStr);
        return res;
    }

    std::string getEncryptedCommand (BleLock *lock)
    {
        return lock->secureConnection.encryptMessageAES(randomField,"UUID");;
    }

protected:
    void serializeExtraFields(json &doc) override {
        doc["key"] = key;
        Log.notice("Serialized key: %s\n", key.c_str());
    }

    void deserializeExtraFields(const json &doc) override {
        key = doc["key"];
        Log.notice("Deserialized key: %s\n", key.c_str());
    }
};



class OpenRequest : public MessageBase {
public:
    std::string key;
    std::string randomField;

    OpenRequest() {
        type = MessageType::OpenRequest;
    }

    void setRandomField(std::string randomFieldVal)
    {
        randomField = randomFieldVal;
    }

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
