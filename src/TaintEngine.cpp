#include "TaintEngine.h"

#include <algorithm>

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"

namespace ct_pass {

void TaintEngine::initialize(const InitialLabels &initialLabels) {
    taintMap.clear();
    memoryTaintMap.clear();

    for (const auto &[value, label] : initialLabels) {
        if (!value) {
            continue;
        }

        taintMap[value] =
            (label == SecrecyLabel::SECRET)
                ? TaintLabel::SECRET
                : TaintLabel::PUBLIC;
    }
}

TaintLabel TaintEngine::labelOf(const llvm::Value *V) const {
    if (!V) {
        return TaintLabel::PUBLIC;
    }

    // LLVM constants do not carry secret input taint.
    if (llvm::isa<llvm::Constant>(V)) {
        return TaintLabel::PUBLIC;
    }

    auto it = taintMap.find(V);
    if (it == taintMap.end()) {
        return TaintLabel::PUBLIC;
    }

    return it->second;
}

const llvm::Value *TaintEngine::memoryKey(const llvm::Value *V) const {
    const llvm::Value *key = V;
    while (key) {
        if (auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(key)) {
            key = GEP->getPointerOperand();
        } else if (auto *CI = llvm::dyn_cast<llvm::CastInst>(key)) {
            key = CI->getOperand(0);
        } else {
            break;
        }
    }
    return key;
}

bool TaintEngine::updateMemoryLabel(const llvm::Value *V, TaintLabel label) {
    const llvm::Value *key = memoryKey(V);
    if (!key || label != TaintLabel::SECRET) {
        return false;
    }

    auto it = memoryTaintMap.find(key);
    if (it == memoryTaintMap.end()) {
        memoryTaintMap[key] = TaintLabel::SECRET;
        return true;
    }

    return false;
}

bool TaintEngine::isSecret(const llvm::Value *V) const {
    return labelOf(V) == TaintLabel::SECRET;
}

bool TaintEngine::updateLabel(
    const llvm::Value *V,
    TaintLabel label
) {
    if (!V || label != TaintLabel::SECRET) {
        return false;
    }

    auto it = taintMap.find(V);

    if (it == taintMap.end()) {
        taintMap[V] = TaintLabel::SECRET;
        return true;
    }

    if (it->second != TaintLabel::SECRET) {
        it->second = TaintLabel::SECRET;
        return true;
    }

    return false;
}

bool TaintEngine::processInstruction(llvm::Instruction &I) {
    bool secret = false;

    /*
     * A value is SECRET if its result depends on at least one
     * SECRET operand. This is the conservative rule used here:
     *
     *   SECRET + PUBLIC -> SECRET
     *   f(SECRET, ...)  -> SECRET
     *   f(PUBLIC, ...)  -> PUBLIC
     *
     * Constants are PUBLIC through labelOf().
     */

    if (auto *PN = llvm::dyn_cast<llvm::PHINode>(&I)) {
        for (unsigned i = 0; i < PN->getNumIncomingValues(); ++i) {
            if (isSecret(PN->getIncomingValue(i))) {
                secret = true;
                break;
            }
        }
    }
    else if (auto *SI = llvm::dyn_cast<llvm::SelectInst>(&I)) {
        secret =
            isSecret(SI->getCondition()) ||
            isSecret(SI->getTrueValue()) ||
            isSecret(SI->getFalseValue());
    }
    else if (auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {
        secret = isSecret(GEP->getPointerOperand());

        if (!secret) {
            for (auto it = GEP->idx_begin(); it != GEP->idx_end(); ++it) {
                if (isSecret(it->get())) {
                    secret = true;
                    break;
                }
            }
        }
    }
    else if (auto *LI = llvm::dyn_cast<llvm::LoadInst>(&I)) {
        // A secret address is a memory-access leak, while a secret value at
        // a public address is only data taint. Keep these concepts separate.
        secret = isSecret(LI->getPointerOperand());

        if (!secret) {
            const llvm::Value *key = memoryKey(LI->getPointerOperand());
            auto it = memoryTaintMap.find(key);
            secret = it != memoryTaintMap.end() &&
                     it->second == TaintLabel::SECRET;
        }
    }
    else if (auto *SI = llvm::dyn_cast<llvm::StoreInst>(&I)) {
        // Store taint belongs to the memory contents, not to the address.
        // Marking the pointer SECRET would incorrectly make every later load
        // from that fixed address look like a secret-dependent access.
        if (isSecret(SI->getValueOperand())) {
            return updateMemoryLabel(SI->getPointerOperand(), TaintLabel::SECRET);
        }
        return false;
    }
    else if (auto *CI = llvm::dyn_cast<llvm::CastInst>(&I)) {
        secret = isSecret(CI->getOperand(0));
    }
    else if (auto *Cmp = llvm::dyn_cast<llvm::CmpInst>(&I)) {
        for (unsigned i = 0; i < Cmp->getNumOperands(); ++i) {
            if (isSecret(Cmp->getOperand(i))) {
                secret = true;
                break;
            }
        }
    }
    else if (auto *BO = llvm::dyn_cast<llvm::BinaryOperator>(&I)) {
        for (unsigned i = 0; i < BO->getNumOperands(); ++i) {
            if (isSecret(BO->getOperand(i))) {
                secret = true;
                break;
            }
        }
    }
    else if (auto *CB = llvm::dyn_cast<llvm::CallBase>(&I)) {
        // Conservative handling for unknown/external calls.
        for (unsigned i = 0; i < CB->arg_size(); ++i) {
            if (isSecret(CB->getArgOperand(i))) {
                secret = true;
                break;
            }
        }
    }
    else {
        // Generic fallback: any secret operand makes the result secret.
        for (unsigned i = 0; i < I.getNumOperands(); ++i) {
            if (isSecret(I.getOperand(i))) {
                secret = true;
                break;
            }
        }
    }

    if (secret && !I.getType()->isVoidTy()) {
        return updateLabel(&I, TaintLabel::SECRET);
    }

    return false;
}

void TaintEngine::analyze(llvm::Function &F) {
    /*
     * The analysis is iterative because an instruction can depend on
     * a value that becomes SECRET later in the scan.
     */
    bool changed = true;

    while (changed) {
        changed = false;

        for (llvm::BasicBlock &BB : F) {
            for (llvm::Instruction &I : BB) {
                if (processInstruction(I)) {
                    changed = true;
                }
            }
        }
    }
}

void TaintEngine::analyze(llvm::Module &M) {
    for (llvm::Function &F : M) {
        if (!F.isDeclaration()) {
            analyze(F);
        }
    }
}

const TaintMap &TaintEngine::getTaintMap() const {
    return taintMap;
}

} // namespace ct_pass
