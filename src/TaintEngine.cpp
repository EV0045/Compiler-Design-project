#include "TaintEngine.h"

#include <algorithm>
<<<<<<< Updated upstream

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
=======
#include <functional>
#include "llvm/IR/CFG.h"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Constants.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
>>>>>>> Stashed changes

namespace ct_pass {

void TaintEngine::initialize(const InitialLabels &initialLabels) {
    taintMap.clear();
    memoryTaintMap.clear();
<<<<<<< Updated upstream
=======
    iterationCount = 0;
>>>>>>> Stashed changes

    for (const auto &[value, label] : initialLabels) {
        if (!value) {
            continue;
        }

<<<<<<< Updated upstream
        taintMap[value] =
            (label == SecrecyLabel::SECRET)
                ? TaintLabel::SECRET
                : TaintLabel::PUBLIC;
=======
        // Pointer secrecy describes pointee contents, not the address itself.
        if (value->getType()->isPointerTy()) {
            taintMap[value] = TaintLabel::PUBLIC;
            if (label == SecrecyLabel::SECRET)
                memoryTaintMap[value] = TaintLabel::SECRET;
        } else {
            taintMap[value] =
                (label == SecrecyLabel::SECRET)
                    ? TaintLabel::SECRET
                    : TaintLabel::PUBLIC;
        }
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
=======
        } else if (auto *PN = llvm::dyn_cast<llvm::PHINode>(key)) {
            // Preserve a common backing object across pointer-valued phis.
            const llvm::Value *common = nullptr;
            bool same = true;
            for (const llvm::Value *incoming : PN->incoming_values()) {
                const llvm::Value *incomingKey = memoryKey(incoming);
                if (!common) common = incomingKey;
                else if (common != incomingKey) { same = false; break; }
            }
            key = (same && common) ? common : key;
            if (key == V || key == PN) break;
        } else if (auto *SI = llvm::dyn_cast<llvm::SelectInst>(key)) {
            const llvm::Value *a = memoryKey(SI->getTrueValue());
            const llvm::Value *b = memoryKey(SI->getFalseValue());
            if (a && a == b) key = a;
            else break;
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
        secret = isSecret(GEP->getPointerOperand());

        if (!secret) {
            for (auto it = GEP->idx_begin(); it != GEP->idx_end(); ++it) {
                if (isSecret(it->get())) {
                    secret = true;
                    break;
                }
=======
        // A public pointer to secret data remains a public address unless
        // an index itself is secret.
        for (auto it = GEP->idx_begin(); it != GEP->idx_end(); ++it) {
            if (isSecret(it->get())) {
                secret = true;
                break;
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
        // Conservative handling for unknown/external calls.
        for (unsigned i = 0; i < CB->arg_size(); ++i) {
            if (isSecret(CB->getArgOperand(i))) {
                secret = true;
                break;
=======
        // Debug/lifetime intrinsics describe IR bookkeeping, not program data
        // operations; treating them as unknown calls causes false memory taint.
        if (llvm::isa<llvm::IntrinsicInst>(CB)) return false;
        bool hasSecretArgument = false;
        for (unsigned i = 0; i < CB->arg_size(); ++i) {
            llvm::Value *arg = CB->getArgOperand(i);
            hasSecretArgument |= isSecret(arg);
            if (arg->getType()->isPointerTy()) {
                const llvm::Value *key = memoryKey(arg);
                auto mem = memoryTaintMap.find(key);
                hasSecretArgument |= mem != memoryTaintMap.end() &&
                                     mem->second == TaintLabel::SECRET;
            }
        }
        secret = hasSecretArgument;
        // Unknown calls may write through output pointers. Conservatively taint
        // pointee memory when any call input is secret.
        if (hasSecretArgument) {
            for (unsigned i = 0; i < CB->arg_size(); ++i) {
                llvm::Value *arg = CB->getArgOperand(i);
                if (arg->getType()->isPointerTy())
                    updateMemoryLabel(arg, TaintLabel::SECRET);
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
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
=======
    // Forward fixed-point iteration in reverse post-order improves convergence.
    llvm::SmallVector<llvm::BasicBlock *, 32> postOrder;
    llvm::SmallPtrSet<llvm::BasicBlock *, 32> visited;
    std::function<void(llvm::BasicBlock *)> dfs = [&](llvm::BasicBlock *BB) {
        if (!BB || !visited.insert(BB).second) return;
        for (llvm::BasicBlock *Succ : llvm::successors(BB)) dfs(Succ);
        postOrder.push_back(BB);
    };
    if (!F.empty()) dfs(&F.getEntryBlock());
    std::reverse(postOrder.begin(), postOrder.end());
    // Include unreachable blocks too, so the analysis is conservative.
    for (llvm::BasicBlock &BB : F)
        if (!visited.count(&BB)) postOrder.push_back(&BB);

    llvm::PostDominatorTree PDT;
    PDT.recalculate(F);
    bool changed = true;
    while (changed) {
        ++iterationCount;
        changed = false;
        for (llvm::BasicBlock *BB : postOrder) {
            for (llvm::Instruction &I : *BB)
                changed |= processInstruction(I);
        }

        // Implicit-flow taint: secret control conditions taint join phis and
        // memory written on paths controlled by the branch, stopping at IPD.
        for (llvm::BasicBlock *BB : postOrder) {
            auto *BI = llvm::dyn_cast<llvm::BranchInst>(BB->getTerminator());
            if (!BI || !BI->isConditional() || !isSecret(BI->getCondition()))
                continue;
            llvm::BasicBlock *Join = nullptr;
            if (auto *Node = PDT.getNode(BB))
                if (auto *IDom = Node->getIDom()) Join = IDom->getBlock();

            llvm::SmallVector<llvm::BasicBlock *, 16> work;
            llvm::SmallPtrSet<llvm::BasicBlock *, 32> controlled;
            work.push_back(BI->getSuccessor(0));
            work.push_back(BI->getSuccessor(1));
            while (!work.empty()) {
                llvm::BasicBlock *Cur = work.pop_back_val();
                if (!Cur || Cur == Join || !controlled.insert(Cur).second) continue;
                for (llvm::Instruction &I : *Cur) {
                    if (auto *SI = llvm::dyn_cast<llvm::StoreInst>(&I))
                        changed |= updateMemoryLabel(SI->getPointerOperand(), TaintLabel::SECRET);
                }
                for (llvm::BasicBlock *Succ : llvm::successors(Cur))
                    if (Succ != Join) work.push_back(Succ);
            }
            if (Join) {
                for (llvm::Instruction &I : *Join) {
                    auto *PN = llvm::dyn_cast<llvm::PHINode>(&I);
                    if (!PN) break;
                    changed |= updateLabel(PN, TaintLabel::SECRET);
>>>>>>> Stashed changes
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
