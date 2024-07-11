#ifndef MESSAGEBASE_H
#define MESSAGEBASE_H

#include <unordered_map>
#include <functional>
#include <string>
#include "json.hpp"
#include <Arduino.h>
#include <ArduinoLog.h>
#include "SecureConnection.h"


using json = nlohmann::json;
/*
#define DECLARE_ENUM_WITH_STRING_CONVERSIONS(name, ...) \
    enum class name { __VA_ARGS__, COUNT }; \
    inline const char* ToString(name v) { \
        static constexpr const char* strings[] = { #__VA_ARGS__ }; \
        return strings[static_cast<int>(v)]; \
    } \
    inline name FromString(const std::string& str) { \
        static constexpr const char* strings[] = { #__VA_ARGS__ }; \
        for (int i = 0; i < static_cast<int>(name::COUNT); ++i) { \
            if (str == strings[i]) { \
                return static_cast<name>(i); \
            } \
        } \
        throw std::invalid_argument("Invalid enum value: " + str); \
    }

DECLARE_ENUM_WITH_STRING_CONVERSIONS(MessageType, ResOk, reqRegKey, OpenRequest, SecurityCheckRequestest,OpenCommand)
*/
enum class MessageType {
    resOk,
    reqRegKey,
    OpenRequest, 
    SecurityCheckRequestest,
    OpenCommand,
    resKey
};

NLOHMANN_JSON_SERIALIZE_ENUM( MessageType, {
    {MessageType::resOk, "resOk"},
    {MessageType::reqRegKey, "reqRegKey"},
    {MessageType::OpenRequest, "OpenRequest"},
    {MessageType::SecurityCheckRequestest, "SecurityCheckRequestest"},
    {MessageType::OpenCommand, "OpenCommand"},
    {MessageType::resKey, "resKey"}
})


class MessageBase {
public:
    std::string sourceAddress;
    std::string destinationAddress;
    MessageType type;
    std::string requestUUID;

    MessageBase() = default;

    virtual std::string serialize();
    virtual MessageBase* processRequest(void* context) { return nullptr; } // Virtual method for processing requests
    virtual ~MessageBase() = default;

    using Constructor = std::function<MessageBase*()>;
    static MessageBase* createInstance(const std::string& input);

    static void registerConstructor(const MessageType &type, Constructor constructor);

    std::string generateUUID();

protected:
    virtual void serializeExtraFields(json& doc) {};
    virtual void deserializeExtraFields(const json& doc) {};

private:
    static std::unordered_map<MessageType, Constructor> constructors;
    void deserialize(const std::string& input);

};

#if 0
class MessageBase {
public:
    std::string sourceAddress;
    std::string destinationAddress;
    MessageType type;
    std::string requestUUID;

    MessageBase() = default;

    virtual std::string serialize();
    virtual MessageBase* processRequest(void* context) { return nullptr; } // Virtual method for processing requests

//    static MessageBase* processRequests(void* context);

    virtual ~MessageBase() = default;

    using Constructor = std::function<MessageBase*()>;
    static MessageBase* createInstance(const std::string& input);

    static void registerConstructor(const MessageType &type, Constructor constructor);

    std::string generateUUID();

    std::string getRandomField();
    void setEncryptedCommand( std::string &encryptedOpenCommand);
    void setDecryptedCommand( std::string &encryptedOpenCommand);

protected:
    virtual void serializeExtraFields(json& doc) = 0;
    virtual void deserializeExtraFields(const json& doc) = 0;

private:
    static std::unordered_map<std::string, Constructor> constructors;
    void deserialize(const std::string& input);

};
#endif
MessageBase* BleLock_request(MessageBase* requestMessage, const std::string& destAddr, uint32_t timeout);

#endif // MESSAGEBASE_H
