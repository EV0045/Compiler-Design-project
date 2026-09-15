#ifndef CONSTANT_TIME_TRANSFORMER_H
#define CONSTANT_TIME_TRANSFORMER_H

#include "ViolationDetector.h"

#include <vector>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

namespace ct_pass {

class ConstantTimeTransformer {
public:
    ConstantTimeTransformer() = default;

    bool transformFunction(
        llvm::Function &F,
        const std::vector<ViolationSite> &violations);

    bool transformModule(
        llvm::Module &M,
        const std::vector<ViolationSite> &violations);

private:
    bool transformBranch(
        llvm::BranchInst *BI);

    bool transformMemory(
        llvm::Instruction *I);

    bool transformGEP(
        llvm::GetElementPtrInst *GEP);
};

}

#endif
