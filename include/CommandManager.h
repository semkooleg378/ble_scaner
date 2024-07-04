#ifndef COMMAND_MANAGER_H
#define COMMAND_MANAGER_H

#include <functional>
#include <unordered_map>
#include <queue>
#include <string>
#include <utility>
#include <Arduino.h>

enum class LColor {
    Reset,
    Red,
    LightRed,
    Yellow,
    LightBlue,
    Green,
    LightCyan
};

void logColor(LColor color, const __FlashStringHelper *format, ...);

class CommandManager {
public:
    using CommandHandler = std::function<void()>;

    void registerHandler(const std::string &command, CommandHandler handler) {
        logColor(LColor::LightBlue, F("registerHandler"));
        handlers[command] = std::move(handler);
    }

    void sendCommand(const std::string &command) {
        logColor(LColor::LightBlue, F("sendCommand"));
        auto *obj = new std::string(command);
        //xQueueSend(commandQueue, &command, portMAX_DELAY);
        xQueueSend(commandQueue, &obj, portMAX_DELAY);
    }

    [[noreturn]] void processCommands() {
        logColor(LColor::LightBlue, F("processCommands"));
        TickType_t xDelay = 10 / portTICK_PERIOD_MS;
        while (true) {
            std::string *command;
            //logColor (LColor::LightCyan, F("proc com loop"));
            if (xQueueReceive(commandQueue, &command, portMAX_DELAY) == pdTRUE) {
                logColor(LColor::LightBlue, F("processCommands BEFORE"));
                if (handlers.find(*command) != handlers.end()) {
                    handlers[*command]();
                    delete command;
                    logColor(LColor::LightBlue, F("processCommands AFTER"));
                }
            }
            vTaskDelay(xDelay);
        }
    }

    void startProcessing() {
        logColor(LColor::LightBlue, F("startProcessing"));
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
