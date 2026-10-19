#include "ViolationDetector.h"
#include "TaintEngine.h"

#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/Support/raw_ostream.h>

namespace ct_pass {

std::string ViolationSite::toString() const {
    std::string str;
    llvm::raw_string_ostream OS(str);

    OS << "[VIOLATION] ";
    if (type == ViolationType::BRANCH_LEAK) {
        OS << "BRANCH_LEAK: ";
    } else {
        OS << "MEMORY_LEAK: ";
    }

    OS << description << "\n";

    if (!sourceLocation.empty()) {
        OS << "  Location: " << sourceLocation << "\n";
    }

    if (instruction) {
        OS << "  Instruction: ";
        instruction->print(OS);
        OS << "\n";
    }

    if (leakingOperand) {
        OS << "  Tainted Operand: ";
        leakingOperand->print(OS);
        OS << "\n";
    }

    return OS.str();
}

void ViolationSite::dump() const {
    llvm::errs() << toString();
}

std::string ViolationDetector::extractSourceLocation(const llvm::Instruction *I) const {
    if (!I) return "";
    const llvm::DebugLoc &DLoc = I->getDebugLoc();
    if (!DLoc) return "";

    std::string locStr;
    llvm::raw_string_ostream OS(locStr);
    DLoc.print(OS);
    return OS.str();
}

bool ViolationDetector::isSecret(const llvm::Value *val, const TaintMap &taintMap) const {
    if (!val) return false;

    // Constants (e.g., immediate values, literals) are always public
    if (llvm::isa<llvm::Constant>(val)) {
        return false;
    }

    auto it = taintMap.find(val);
    if (it != taintMap.end()) {
        return it->second == TaintLabel::SECRET;
    }

    return false;
}

std::vector<llvm::Instruction*> ViolationDetector::isolateCandidateInstructions(llvm::Function &F) {
    std::vector<llvm::Instruction*> candidates;

    // Instruction Walker: Traverse all Basic Blocks and Instructions
    for (llvm::BasicBlock &BB : F) {
        for (llvm::Instruction &I : BB) {
            // 1. Conditional branch instructions
            if (auto *BI = llvm::dyn_cast<llvm::BranchInst>(&I)) {
                if (BI->isConditional()) {
                    candidates.push_back(&I);
                }
            }
            // 2. Memory load instructions
            else if (llvm::isa<llvm::LoadInst>(&I)) {
                candidates.push_back(&I);
            }
            // 3. Memory store instructions
            else if (llvm::isa<llvm::StoreInst>(&I)) {
                candidates.push_back(&I);
            }
            // 4. Address calculations (GetElementPtr)
            else if (llvm::isa<llvm::GetElementPtrInst>(&I)) {
                candidates.push_back(&I);
            }
        }
    }

    return candidates;
}

bool ViolationDetector::inspectBranch(llvm::BranchInst *BI, 
                                     const TaintMap &taintMap, 
                                     ViolationSite &outSite) {
    if (!BI || !BI->isConditional()) {
        return false;
    }

    llvm::Value *cond = BI->getCondition();
    if (isSecret(cond, taintMap)) {
        outSite.instruction = BI;
        outSite.type = ViolationType::BRANCH_LEAK;
        outSite.leakingOperand = cond;
        outSite.description = "Conditional branch depends on secret data (control-flow timing side channel)";
        outSite.sourceLocation = extractSourceLocation(BI);
        return true;
    }

    return false;
}

bool ViolationDetector::inspectMemory(llvm::Instruction *I, 
                                     const TaintMap &taintMap, 
                                     ViolationSite &outSite) {
    if (!I) return false;

    if (auto *LI = llvm::dyn_cast<llvm::LoadInst>(I)) {
        llvm::Value *ptr = LI->getPointerOperand();
        if (isSecret(ptr, taintMap)) {
            outSite.instruction = LI;
            outSite.type = ViolationType::MEMORY_LEAK;
            outSite.leakingOperand = ptr;
            outSite.description = "Memory load from secret-dependent address (cache-timing side channel)";
            outSite.sourceLocation = extractSourceLocation(LI);
            return true;
        }
    } else if (auto *SI = llvm::dyn_cast<llvm::StoreInst>(I)) {
        llvm::Value *ptr = SI->getPointerOperand();
        if (isSecret(ptr, taintMap)) {
            outSite.instruction = SI;
            outSite.type = ViolationType::MEMORY_LEAK;
            outSite.leakingOperand = ptr;
            outSite.description = "Memory store to secret-dependent address (cache-timing side channel)";
            outSite.sourceLocation = extractSourceLocation(SI);
            return true;
        }
    }

    return false;
}

bool ViolationDetector::inspectGEP(llvm::GetElementPtrInst *GEP, 
                                  const TaintMap &taintMap, 
                                  ViolationSite &outSite) {
    if (!GEP) return false;

    // Check if the base pointer itself is secret
    llvm::Value *ptr = GEP->getPointerOperand();
    if (isSecret(ptr, taintMap)) {
        outSite.instruction = GEP;
        outSite.type = ViolationType::MEMORY_LEAK;
        outSite.leakingOperand = ptr;
        outSite.description = "Pointer arithmetic on secret base address (cache-timing side channel)";
        outSite.sourceLocation = extractSourceLocation(GEP);
        return true;
    }

    // Check if any indexing offset is secret (e.g. table[secret])
    for (auto it = GEP->idx_begin(); it != GEP->idx_end(); ++it) {
        llvm::Value *idx = it->get();
        if (isSecret(idx, taintMap)) {
            outSite.instruction = GEP;
            outSite.type = ViolationType::MEMORY_LEAK;
            outSite.leakingOperand = idx;
            outSite.description = "Secret-dependent index calculation in GetElementPtr (cache lookup side channel)";
            outSite.sourceLocation = extractSourceLocation(GEP);
            return true;
        }
    }

    return false;
}

std::vector<ViolationSite> ViolationDetector::detectViolations(llvm::Function &F, 
                                                              const TaintMap &taintMap) {
    std::vector<ViolationSite> violations;

    for (llvm::BasicBlock &BB : F) {
        for (llvm::Instruction &I : BB) {
            ViolationSite site;

            if (auto *BI = llvm::dyn_cast<llvm::BranchInst>(&I)) {
                if (inspectBranch(BI, taintMap, site)) {
                    violations.push_back(site);
                }
            } else if (auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {
                if (inspectGEP(GEP, taintMap, site)) {
                    violations.push_back(site);
                }
            } else if (llvm::isa<llvm::LoadInst>(&I) || llvm::isa<llvm::StoreInst>(&I)) {
                if (inspectMemory(&I, taintMap, site)) {
                    violations.push_back(site);
                }
            }
        }
    }

    return violations;
}

std::vector<ViolationSite> ViolationDetector::detectViolations(llvm::Module &M, 
                                                              const TaintMap &taintMap) {
    std::vector<ViolationSite> allViolations;

    for (llvm::Function &F : M) {
        if (!F.isDeclaration()) {
            auto funcViolations = detectViolations(F, taintMap);
            allViolations.insert(allViolations.end(), funcViolations.begin(), funcViolations.end());
        }
    }

    return allViolations;
}

bool ViolationDetector::verifyZeroLeaks(llvm::Function &F,
                                       const TaintMap &taintMap,
                                       std::vector<ViolationSite> &remainingLeaks) {
    remainingLeaks = detectViolations(F, taintMap);
    return remainingLeaks.empty();
}

// ---------------------------------------------------------------------------
// Week 2 Integration: TaintEngine convenience overloads
// These bridge Member 3's TaintEngine output directly into the detector,
// so callers do not need to manually extract getTaintMap().
// ---------------------------------------------------------------------------

std::vector<ViolationSite>
ViolationDetector::detectViolations(llvm::Function &F, const TaintEngine &engine) {
    return detectViolations(F, engine.getTaintMap());
}

std::vector<ViolationSite>
ViolationDetector::detectViolations(llvm::Module &M, const TaintEngine &engine) {
    return detectViolations(M, engine.getTaintMap());
}

bool ViolationDetector::verifyZeroLeaks(llvm::Function &F,
                                       const TaintEngine &engine,
                                       std::vector<ViolationSite> &remainingLeaks) {
    return verifyZeroLeaks(F, engine.getTaintMap(), remainingLeaks);
}

// ---------------------------------------------------------------------------
// Week 3 Deliverable: Module-level post-transformation verification
// ---------------------------------------------------------------------------

bool ViolationDetector::verifyZeroLeaks(llvm::Module &M,
                                       const TaintMap &taintMap,
                                       std::vector<ViolationSite> &remainingLeaks) {
    remainingLeaks.clear();

    for (llvm::Function &F : M) {
        if (F.isDeclaration()) {
            continue; // skip external function prototypes
        }

        std::vector<ViolationSite> funcLeaks;
        verifyZeroLeaks(F, taintMap, funcLeaks);

        remainingLeaks.insert(
            remainingLeaks.end(),
            funcLeaks.begin(),
            funcLeaks.end()
        );
    }

    return remainingLeaks.empty();
}

bool ViolationDetector::verifyZeroLeaks(llvm::Module &M,
                                       const TaintEngine &engine,
                                       std::vector<ViolationSite> &remainingLeaks) {
    return verifyZeroLeaks(M, engine.getTaintMap(), remainingLeaks);
}

} // namespace ct_pass
