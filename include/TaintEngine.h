#ifndef TAINT_ENGINE_H
#define TAINT_ENGINE_H

#include <map>
#include <unordered_map>

#include "SecrecyLabeller.h"
#include "ViolationDetector.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"

namespace ct_pass {

/**
 * Member 3: propagates the initial secrecy labels produced by
 * SecrecyLabeller through LLVM IR.
 *
 * The output TaintMap is the exact data contract consumed by
 * ViolationDetector.
 */
class TaintEngine {
public:
    using InitialLabels =
        std::map<const llvm::Value*, SecrecyLabel>;

    // Start a fresh analysis using Member 1's labels.
    void initialize(const InitialLabels &initialLabels);

    // Propagate taint until a fixed point is reached.
    void analyze(llvm::Function &F);

    // Analyze all defined functions in a module.
    void analyze(llvm::Module &M);

    // Exact output expected by Member 2.
    const TaintMap &getTaintMap() const;

    // Convenience query for the current result.
    bool isSecret(const llvm::Value *V) const;

private:
    TaintMap taintMap;
    std::unordered_map<const llvm::Value*, TaintLabel> memoryTaintMap;

    const llvm::Value *memoryKey(const llvm::Value *V) const;
    bool updateMemoryLabel(const llvm::Value *V, TaintLabel label);
    bool updateLabel(const llvm::Value *V, TaintLabel label);
    TaintLabel labelOf(const llvm::Value *V) const;
    bool processInstruction(llvm::Instruction &I);
};

} // namespace ct_pass

#endif
