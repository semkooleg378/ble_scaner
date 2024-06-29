#include "ReqRegKey.h"

ReqRegKey::ReqRegKey(const std::string& sourceAddress, const std::string& destinationAddress, const std::string& key)
    : MessageBase("reqRegKey", sourceAddress, destinationAddress), key(key) {}

nlohmann::json ReqRegKey::toJson() const {
    nlohmann::json jsonObj = MessageBase::toJson(); // Get base class JSON
    jsonObj["key"] = key;
    return jsonObj;
}

std::string ReqRegKey::serialize() const {
    return toJson().dump();
}

std::unique_ptr<MessageBase> MessageBase::createInstance(const std::string& jsonString) {
    nlohmann::json jsonObj = nlohmann::json::parse(jsonString);
    std::string type = jsonObj["type"];
    std::string sourceAddress = jsonObj["sourceAddress"];
    std::string destinationAddress = jsonObj["destinationAddress"];
    
    if (type == "resOk") {
        bool status = jsonObj["status"];
        return std::make_unique<ResOk>(sourceAddress, destinationAddress, status);
    } else if (type == "reqRegKey") {
        std::string key = jsonObj["key"];
        return std::make_unique<ReqRegKey>(sourceAddress, destinationAddress, key);
    }
    // Add other message types as needed
    return std::make_unique<MessageBase>(type, sourceAddress, destinationAddress);
}
