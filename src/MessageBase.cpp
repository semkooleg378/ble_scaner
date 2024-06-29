#include "MessageBase.h"

MessageBase::MessageBase(const std::string& type, const std::string& sourceAddress, const std::string& destinationAddress)
    : type(type), sourceAddress(sourceAddress), destinationAddress(destinationAddress) {}

nlohmann::json MessageBase::toJson() const {
    nlohmann::json jsonObj;
    jsonObj["type"] = type;
    jsonObj["sourceAddress"] = sourceAddress;
    jsonObj["destinationAddress"] = destinationAddress;
    return jsonObj;
}

std::string MessageBase::serialize() const {
    return toJson().dump();
}
/**
std::unique_ptr<MessageBase> MessageBase::createInstance(const std::string& jsonString) {
    nlohmann::json jsonObj = nlohmann::json::parse(jsonString);
    std::string type = jsonObj["type"];
    std::string sourceAddress = jsonObj["sourceAddress"];
    std::string destinationAddress = jsonObj["destinationAddress"];
    if (type == "resOk") {
        bool status = jsonObj["status"];
        return std::make_unique<ResOk>(sourceAddress, destinationAddress, status);
    }
    // Add other message types as needed
    return std::make_unique<MessageBase>(type, sourceAddress, destinationAddress);
}
*/

ResOk::ResOk(const std::string& sourceAddress, const std::string& destinationAddress, bool status)
    : MessageBase("resOk", sourceAddress, destinationAddress), status(status) {}

nlohmann::json ResOk::toJson() const {
    nlohmann::json jsonObj = MessageBase::toJson(); // Get base class JSON
    jsonObj["status"] = status;
    return jsonObj;
}

std::string ResOk::serialize() const {
    return toJson().dump();
}
