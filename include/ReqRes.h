#include <MessageBase.h>
#include "BleLockClient.h"

#define MessageMaxDelay 30000

extern volatile bool isOkRes;

enum class MessageTypeReg {
    resOk,
    reqRegKey,
    OpenRequest, 
    SecurityCheckRequestest,
    OpenCommand,
    resKey, 
    HelloRequest,
    ReceivePublic
};

/*enum KeyStatusType
{
    statusWaitForAnswer,
    statusNone,
    statusPublickKeyExist,
    statusSessionKeyCreated,
    statusOpenCommand,
    statusEnd
};
*/
//extern std::unordered_map<std::string, KeyStatusType> Locks;

extern std::unordered_map<std::string, KeyStatusType> LocksLastCall;



class ResOk : public MessageBase {
public:
    bool status{};

    ResOk() {
        type = (MessageType)MessageTypeReg::resOk;
        requestUUID = generateUUID();
    }

    explicit ResOk(bool status) : status(status) {
        type = (MessageType)MessageTypeReg::resOk;
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
        auto lock = static_cast<BleLockClient *>(context);
        isFinalMessage = true;
        if (status)
        {
            if (LocksLastCall[sourceAddress] == KeyStatusType::statusNone)
                BleLockClient::Locks[sourceAddress] = KeyStatusType::statusSessionKeyCreated;
            else
            if (LocksLastCall[sourceAddress] == KeyStatusType::statusPublickKeyExist)
                BleLockClient::Locks[sourceAddress] = KeyStatusType::statusSessionKeyCreated;
            else
                BleLockClient::Locks[sourceAddress] = KeyStatusType::statusEnd;
        }
        else
        {
            if (LocksLastCall[sourceAddress] == KeyStatusType::statusNone)
                BleLockClient::Locks[sourceAddress] = KeyStatusType::statusEnd;
            else
            if (LocksLastCall[sourceAddress] == KeyStatusType::statusPublickKeyExist)
                BleLockClient::Locks[sourceAddress] = KeyStatusType::statusNone;
            else
                BleLockClient::Locks[sourceAddress] = KeyStatusType::statusEnd;
        }
        return nullptr;
    }
};


class ResKey : public MessageBase {
public:
    bool status{};
    std::string key{};

    ResKey() {
        type = (MessageType)MessageTypeReg::resKey;
        requestUUID = generateUUID();
    }

    explicit ResKey(bool status, std::string newKey) : status(status), key(newKey) {
        type = (MessageType)MessageTypeReg::resKey;
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
        auto lock = static_cast<BleLockClient *>(context);
        //isOkRes = true;
        //lock->secureConnection.SetAESKey(sourceAddress,key); 
        isFinalMessage = true;

        if (status)
            BleLockClient::Locks[sourceAddress] = KeyStatusType::statusOpenCommand;
        else
            BleLockClient::Locks[sourceAddress] = KeyStatusType::statusEnd;// fail
        return nullptr;
    }
};



class ReqRegKey : public MessageBase {
public:
    std::string key;

    ReqRegKey() {
        type = (MessageType)MessageTypeReg::reqRegKey;
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
        type = (MessageType)MessageTypeReg::OpenCommand;
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
        type = (MessageType)MessageTypeReg::SecurityCheckRequestest;
        requestUUID = generateUUID();
    }

    void setRandomField(std::string randomFieldVal)
    {
        randomField = randomFieldVal;
    }
    MessageBase *processRequest(void *context) override {
        auto lock = static_cast<BleLockClient *>(context);
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

    std::string getEncryptedCommand (BleLockClient *lock)
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
        type = (MessageType)MessageTypeReg::OpenRequest;
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

////////////////////////
///////////////////////
////////////////////////
//#define SERVER_PART

class ReceivePublic : public MessageBase {
public:
    std::string key;

    ReceivePublic() {
        type = (MessageType)MessageTypeReg::ReceivePublic;
    }

    explicit ReceivePublic(std::string newKey) :  key(newKey) {
        type = (MessageType)MessageTypeReg::ReceivePublic;
    }
protected:

    void serializeExtraFields(json &doc) override {
        doc["key"] = key;
        Serial.printf("Serialized key:%s\n", key.c_str());
    }

    void deserializeExtraFields(const json &doc) override {
        key = doc["key"];
        Serial.printf("Deserialized key:%s\n", key.c_str());
    }
    MessageBase *processRequest(void *context) override {
        isFinalMessage = true;
        auto lock = static_cast<BleLockClient *>(context);

        auto pubKey = SecureConnection::hex2vector(key);
        std::pair pair (pubKey,pubKey);
        lock->secureConnection.keys[sourceAddress] = pair;
        lock->secureConnection.SaveRSAKeys();
        BleLockClient::Locks[sourceAddress] = KeyStatusType::statusPublickKeyExist;
        return nullptr;
    }

};
// cliewnt handshake request
class HelloRequest : public MessageBase {
public:
    bool status{};
    std::string key;

    HelloRequest() {
        type = (MessageType)MessageTypeReg::HelloRequest;
    }

    explicit HelloRequest(bool status, std::string newKey) : status(status), key(newKey) {
        type = (MessageType)MessageTypeReg::HelloRequest;
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
        auto lock = static_cast<BleLockClient *>(context);
        if (status) //handshake suceeded  check key and send Ok
        {
            bool bChkResult = false;
            auto keyPair = lock->secureConnection.keys.find(sourceAddress);
            if (keyPair!=lock->secureConnection.keys.end())
            {
                //keyPair->second.first;
                //keyPair->second.second;
                auto rawMessage = SecureConnection::hex2vector (key);
                std::string encMessage  = std::string ((char*)rawMessage.data(),rawMessage.size()); 
                std::vector<uint8_t> encryptAESKey = lock->secureConnection.decryptMessageRSA (encMessage,sourceAddress);
                lock->secureConnection.SetAESKey(sourceAddress, SecureConnection::vector2hex(encryptAESKey));
            }
            auto res = new ResOk();
            res->destinationAddress = sourceAddress;
            res->sourceAddress = destinationAddress;
            res->status = bChkResult;
            return res;
        }
        else // sdend publick key
        {
            if (lock->secureConnection.keys.empty())
            {
                lock->secureConnection.generateRSAKeys (sourceAddress);
            }
            else
            {
                lock->secureConnection.generateRSAPublicKeys (sourceAddress);
            }
            lock->secureConnection.SaveRSAKeys();

            auto res = new ReceivePublic;

            res->destinationAddress = sourceAddress;
            res->sourceAddress = destinationAddress;            
            res->key = SecureConnection::vector2hex(lock->secureConnection.keys[sourceAddress].first);
            return res;
        }
        return nullptr;
    }
};

