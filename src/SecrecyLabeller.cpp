#include "SecrecyLabeller.h"

#include <fstream>
#include <iostream>

#include "llvm/IR/Argument.h"
#include "llvm/Support/JSON.h"

using namespace llvm;

bool SecrecyLabeller::loadConfig(const std::string &configPath) {
    //gets config file path and reads it into a string 
    std::ifstream file(configPath);

    if (!file.is_open()) {
        std::cerr << "Error: Could not open config file: "
                  << configPath << std::endl;
        return false;
    }

    std::string jsonText(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    //llvm json parser
    auto parsed = json::parse(jsonText);

    if (!parsed) {
        std::cerr << "Error: Invalid JSON configuration."
                  << std::endl;
        return false;
    }

    auto *object = parsed->getAsObject();

    if (!object) {
        std::cerr << "Error: JSON root must be an object."
                  << std::endl;
        return false;
    }

    parameterLabels.clear();

    // Read secret parameters
    if (auto secretArray = object->getArray("secret_parameters")) {

        for (const auto &value : *secretArray) {

            if (auto name = value.getAsString()) {
                parameterLabels[name->str()] =
                    SecrecyLabel::SECRET;
            }
        }
    }

    // Read public parameters
    if (auto publicArray = object->getArray("public_parameters")) {

        for (const auto &value : *publicArray) {

            if (auto name = value.getAsString()) {
                parameterLabels[name->str()] =
                    SecrecyLabel::PUBLIC;
            }
        }
    }

    return true;
}


SecrecyLabel SecrecyLabeller::getLabel(
    const std::string &parameterName
) const {

    auto it = parameterLabels.find(parameterName);
    //This checks your internal map (which was loaded from the JSON file) to see if the name exists.

    if (it != parameterLabels.end()) {
        return it->second;// Return whether it's SECRET or PUBLIC
    }

    // Anything not explicitly marked secret
    // is treated as PUBLIC.
    return SecrecyLabel::PUBLIC;
}


std::map<const llvm::Value*, SecrecyLabel>
SecrecyLabeller::labelFunction(
    const llvm::Function &function
) {

    std::map<const llvm::Value*, SecrecyLabel> labels;

    for (const llvm::Argument &argument : function.args()) {

        std::string name = argument.getName().str();

        SecrecyLabel label = getLabel(name);// Check map via getLabel

        labels[&argument] = label;// Map the LLVM memory address to its label
    }

    return labels;
}


void SecrecyLabeller::printLabels(
    const std::map<const llvm::Value*, SecrecyLabel> &labels
) const {

    std::cout << "Initial Secrecy Labels:\n";

    for (const auto &[value, label] : labels) {

        std::string name = value->getName().str();

        std::cout << "  "
                  << name
                  << " -> ";

        if (label == SecrecyLabel::SECRET) {
            std::cout << "SECRET";
        }
        else {
            std::cout << "PUBLIC";
        }

        std::cout << "\n";
    }
}
