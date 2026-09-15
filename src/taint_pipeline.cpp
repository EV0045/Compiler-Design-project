#include "SecrecyLabeller.h"
#include "TaintEngine.h"
#include "ViolationDetector.h"

#include <iostream>
#include <memory>
#include <string>
#include <fstream>

#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SourceMgr.h"

static std::string getFunctionNameFromConfig(
    const std::string &configPath
) {
    std::ifstream file(configPath);

    if (!file.is_open()) {
        return "";
    }

    std::string jsonText(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    auto parsed = llvm::json::parse(jsonText);

    if (!parsed) {
        return "";
    }

    if (auto *object = parsed->getAsObject()) {
        if (auto functionName = object->getString("function")) {
            return functionName->str();
        }
    }

    return "";
}

static const char *labelName(ct_pass::TaintLabel label) {
    return label == ct_pass::TaintLabel::SECRET
        ? "SECRET"
        : "PUBLIC";
}

static const char *violationName(ct_pass::ViolationType type) {
    return type == ct_pass::ViolationType::BRANCH_LEAK
        ? "BRANCH_LEAK"
        : "MEMORY_LEAK";
}

int main(int argc, char **argv) {
    if (argc != 3) {
        std::cerr
            << "Usage: member3_pipeline <input.ll> <config.json>\n";
        return 1;
    }

    const std::string irFile = argv[1];
    const std::string configFile = argv[2];

    const std::string functionName =
        getFunctionNameFromConfig(configFile);

    if (functionName.empty()) {
        std::cerr
            << "Error: Could not read 'function' from config: "
            << configFile << "\n";
        return 1;
    }

    llvm::LLVMContext context;
    llvm::SMDiagnostic error;

    std::unique_ptr<llvm::Module> module =
        llvm::parseIRFile(irFile, error, context);

    if (!module) {
        error.print("member3_pipeline", llvm::errs());
        return 1;
    }

    llvm::Function *function =
        module->getFunction(functionName);

    if (!function) {
        std::cerr
            << "Error: Function '" << functionName
            << "' not found in " << irFile << ".\n";
        return 1;
    }

    // ------------------------------------------------------------
    // STEP 1: Member 1 - initial secrecy labels
    // ------------------------------------------------------------
    SecrecyLabeller labeller;

    if (!labeller.loadConfig(configFile)) {
        return 1;
    }

    auto initialLabels =
        labeller.labelFunction(*function);

    labeller.printLabels(initialLabels);

    // ------------------------------------------------------------
    // STEP 2: Member 3 - taint propagation
    // ------------------------------------------------------------
    ct_pass::TaintEngine engine;
    engine.initialize(initialLabels);
    engine.analyze(*function);

    const ct_pass::TaintMap &taintMap =
        engine.getTaintMap();

    std::cout << "\nPropagated Taint Labels:\n";

    for (const auto &[value, label] : taintMap) {
        if (!value) {
            continue;
        }

        std::string name = value->getName().str();

        if (name.empty()) {
            continue;
        }

        std::cout
            << "  "
            << name
            << " -> "
            << labelName(label)
            << "\n";
    }

    // ------------------------------------------------------------
    // STEP 3: Member 2 - consume Member 3's TaintMap
    // ------------------------------------------------------------
    ct_pass::ViolationDetector detector;

    auto violations =
        detector.detectViolations(*function, taintMap);

    std::cout << "\nDetected Violations: "
              << violations.size()
              << "\n";

    for (const auto &violation : violations) {
        std::cout
            << "  "
            << violationName(violation.type)
            << "\n"
            << "    "
            << violation.description
            << "\n";

        if (violation.instruction) {
            std::cout << "    Instruction: ";
            violation.instruction->print(llvm::outs());
            std::cout << "\n";
        }
    }

    return violations.empty() ? 0 : 2;
}
