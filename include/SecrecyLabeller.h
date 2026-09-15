#ifndef SECRECY_LABELLER_H
#define SECRECY_LABELLER_H

#include <map>
#include <string>

#include "llvm/IR/Function.h"
#include "llvm/IR/Value.h"

enum class SecrecyLabel {
    SECRET,
    PUBLIC
};

class SecrecyLabeller {
private:
    std::map<std::string, SecrecyLabel> parameterLabels;

public:
    // Loads SECRET/PUBLIC information from JSON config
    bool loadConfig(const std::string &configPath);

    // Labels the arguments of an LLVM function
    std::map<const llvm::Value*, SecrecyLabel>
    labelFunction(const llvm::Function &function);

    // Prints the generated labels
    void printLabels(
        const std::map<const llvm::Value*, SecrecyLabel> &labels
    ) const;

private:
    SecrecyLabel getLabel(const std::string &parameterName) const;
};

#endif