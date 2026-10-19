#include "SecrecyLabeller.h" 
 
#include <iostream> 
#include <memory> 
#include <fstream> 
 
#include "llvm/IR/LLVMContext.h" 
#include "llvm/IR/Module.h" 
#include "llvm/IRReader/IRReader.h" 
#include "llvm/Support/SourceMgr.h" 
#include "llvm/Support/JSON.h" 
 
// Helper function to read the function name from the JSON config 
std::string getFunctionNameFromConfig(const std::string &configFile) { 
    std::ifstream file(configFile); 
    if (!file.is_open()) return ""; 
 
    std::string jsonText( 
        (std::istreambuf_iterator<char>(file)), 
        std::istreambuf_iterator<char>() 
    ); 
 
    auto parsed = llvm::json::parse(jsonText); 
    if (!parsed) return ""; 
 
    if (auto *object = parsed->getAsObject()) { 
        if (auto funcName = object->getString("function")) { 
            return funcName->str(); 
        } 
    } 
    return ""; 
} 
//takes input from terminal and reads into argc and argv  
int main(int argc, char **argv) { 
 
    if (argc != 3) { 
        std::cerr << "Usage: labeller_test <input.ll> <config.json>\n"; 
        return 1; 
    } 
 
    const char *irFile = argv[1]; 
    const char *configFile = argv[2]; 
 
    // 1. Read the target function name from the JSON config dynamically 
    std::string targetFuncName = getFunctionNameFromConfig(configFile); 
    if (targetFuncName.empty()) { 
        std::cerr << "Error: Could not read 'function' name from config: " << configFile << "\n"; 
        return 1; 
    } 
 
    llvm::LLVMContext context; 
    llvm::SMDiagnostic error; 
 
    std::unique_ptr<llvm::Module> module = 
        llvm::parseIRFile( 
            irFile, 
            error, 
            context 
        ); 
 
    if (!module) { 
        error.print("labeller_test", llvm::errs()); 
        return 1; 
    } 
 
    SecrecyLabeller labeller; 
 
    if (!labeller.loadConfig(configFile)) { 
        return 1; 
    } 
 
    // 2. Search for the dynamically retrieved function name 
    llvm::Function *function = 
        module->getFunction(targetFuncName); 
 
    if (!function) { 
        std::cerr 
            << "Error: Function '" << targetFuncName << "' not found in " << irFile << ".\n"; 
        return 1; 
    } 
 
    auto labels = 
        labeller.labelFunction(*function); 
 
    labeller.printLabels(labels); 
 
    return 0; 
}  
