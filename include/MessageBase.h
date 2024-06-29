#ifndef MESSAGE_BASE_H
#define MESSAGE_BASE_H

#include <string>
#include <memory>
#include "json.hpp"

class MessageBase {
public:
    std::string type;
    std::string sourceAddress;
    std::string destinationAddress;

    MessageBase(const std::string& type, const std::string& sourceAddress, const std::string& destinationAddress);
    virtual ~MessageBase() = default;

    virtual nlohmann::json toJson() const;
    virtual std::string serialize() const;

    static std::unique_ptr<MessageBase> createInstance(const std::string& jsonString);
};

// Derived message class for demonstration
class ResOk : public MessageBase {
public:
    bool status;

    ResOk(const std::string& sourceAddress, const std::string& destinationAddress, bool status);
    nlohmann::json toJson() const override;
    std::string serialize() const override;
};

#endif // MESSAGE_BASE_H
