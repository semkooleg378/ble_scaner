#ifndef COMMAND_MANAGER_H
#define COMMAND_MANAGER_H

#include <functional>
#include <unordered_map>
#include <queue>
#include <string>
#include <utility>
#include <Arduino.h>

class CommandManager {
public:
    using CommandHandler = std::function<void()>;

    void registerHandler(const std::string &command, CommandHandler handler) {
        handlers[command] = std::move(handler);
    }

    void sendCommand(const std::string &command) {
        xQueueSend(commandQueue, &command, portMAX_DELAY);
    }

    [[noreturn]] void processCommands() {
        while (true) {
            std::string command;
            if (xQueueReceive(commandQueue, &command, portMAX_DELAY) == pdTRUE) {
                if (handlers.find(command) != handlers.end()) {
                    handlers[command]();
                }
            }
        }
    }

    void startProcessing() {
        xTaskCreate([](void *parameter) {
            static_cast<CommandManager *>(parameter)->processCommands();
        }, "CommandProcessorTask", 8192, this, 1, nullptr);
    }

    CommandManager() {
        commandQueue = xQueueCreate(10, sizeof(std::string));
    }

    ~CommandManager() {
        vQueueDelete(commandQueue);
    }

private:
    std::unordered_map<std::string, CommandHandler> handlers;
    QueueHandle_t commandQueue;
};

#endif // COMMAND_MANAGER_H
