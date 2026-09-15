#include "ConstantTimeTransformer.h"

#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

namespace ct_pass {

bool ConstantTimeTransformer::transformFunction(
    llvm::Function &F,
    const std::vector<ViolationSite> &violations) {

    bool changed = false;

    for (const ViolationSite &site : violations) {
        if (!site.instruction) {
            continue;
        }

        if (site.type == ViolationType::BRANCH_LEAK) {
            auto *BI =
                llvm::dyn_cast<llvm::BranchInst>(site.instruction);

            if (BI && transformBranch(BI)) {
                changed = true;
            }
        }
    }

    for (const ViolationSite &site : violations) {
        if (!site.instruction) {
            continue;
        }

        if (site.type != ViolationType::MEMORY_LEAK) {
            continue;
        }

        if (auto *GEP =
                llvm::dyn_cast<llvm::GetElementPtrInst>(
                    site.instruction)) {

            if (transformGEP(GEP)) {
                changed = true;
            }
        } else {
            if (transformMemory(site.instruction)) {
                changed = true;
            }
        }
    }

    return changed;
}

bool ConstantTimeTransformer::transformModule(
    llvm::Module &M,
    const std::vector<ViolationSite> &violations) {

    bool changed = false;

    for (const ViolationSite &site : violations) {
        if (!site.instruction) {
            continue;
        }

        llvm::Function *F =
            site.instruction->getFunction();

        if (F && transformFunction(*F, {site})) {
            changed = true;
        }
    }

    return changed;
}

bool ConstantTimeTransformer::transformBranch(
    llvm::BranchInst *BI) {

    if (!BI || !BI->isConditional()) {
        return false;
    }

    llvm::BasicBlock *ThenBlock =
        BI->getSuccessor(0);

    llvm::BasicBlock *ElseBlock =
        BI->getSuccessor(1);

    if (!ThenBlock || !ElseBlock) {
        return false;
    }

    auto *ThenBranch =
        llvm::dyn_cast<llvm::BranchInst>(
            ThenBlock->getTerminator());

    auto *ElseBranch =
        llvm::dyn_cast<llvm::BranchInst>(
            ElseBlock->getTerminator());

    if (!ThenBranch || !ElseBranch ||
        ThenBranch->isConditional() ||
        ElseBranch->isConditional()) {
        return false;
    }

    llvm::BasicBlock *MergeBlock =
        ThenBranch->getSuccessor(0);

    if (!MergeBlock ||
        ElseBranch->getSuccessor(0) != MergeBlock) {
        return false;
    }

    llvm::PHINode *Phi = nullptr;

    for (llvm::Instruction &I : *MergeBlock) {
        if (auto *P =
                llvm::dyn_cast<llvm::PHINode>(&I)) {

            if (Phi) {
                return false;
            }

            Phi = P;
        } else {
            break;
        }
    }

    if (!Phi || Phi->getNumIncomingValues() != 2) {
        return false;
    }

    if (Phi->getIncomingBlock(0) != ThenBlock &&
        Phi->getIncomingBlock(1) != ThenBlock) {
        return false;
    }

    if (Phi->getIncomingBlock(0) != ElseBlock &&
        Phi->getIncomingBlock(1) != ElseBlock) {
        return false;
    }

    llvm::Value *ThenValue =
        Phi->getIncomingValueForBlock(ThenBlock);

    llvm::Value *ElseValue =
        Phi->getIncomingValueForBlock(ElseBlock);

    for (llvm::Instruction &I : *ThenBlock) {
        if (&I == ThenBranch) {
            break;
        }

        if (llvm::isa<llvm::PHINode>(&I) ||
            !llvm::isSafeToSpeculativelyExecute(&I)) {
            return false;
        }
    }

    for (llvm::Instruction &I : *ElseBlock) {
        if (&I == ElseBranch) {
            break;
        }

        if (llvm::isa<llvm::PHINode>(&I) ||
            !llvm::isSafeToSpeculativelyExecute(&I)) {
            return false;
        }
    }

    llvm::Value *Condition =
        BI->getCondition();

    for (auto It = ThenBlock->begin();
         It != ThenBranch->getIterator();) {

        llvm::Instruction *I = &*It++;
        I->moveBefore(BI);
    }

    for (auto It = ElseBlock->begin();
         It != ElseBranch->getIterator();) {

        llvm::Instruction *I = &*It++;
        I->moveBefore(BI);
    }

    auto *Select =
        llvm::SelectInst::Create(
            Condition,
            ThenValue,
            ElseValue,
            "ct.select",
            BI);

    Phi->replaceAllUsesWith(Select);
    Phi->eraseFromParent();

    llvm::BranchInst *NewBranch =
        llvm::BranchInst::Create(MergeBlock);

    llvm::ReplaceInstWithInst(
        BI,
        NewBranch);

    ThenBranch->eraseFromParent();
    ElseBranch->eraseFromParent();

    ThenBlock->removeFromParent();
    ElseBlock->removeFromParent();

    delete ThenBlock;
    delete ElseBlock;

    return true;
}

bool ConstantTimeTransformer::transformMemory(
    llvm::Instruction *I) {

   if (!I || I->getParent() == nullptr) {
    return false;
	}

    auto *LI =
        llvm::dyn_cast<llvm::LoadInst>(I);

    if (!LI) {
        return false;
    }


        << "TRANSFORMER: Load violation found\n";

    auto *GEP =
        llvm::dyn_cast<llvm::GetElementPtrInst>(
            LI->getPointerOperand());

    if (!GEP) {
        llvm::errs()
            << "TRANSFORMER: Load is not using a GEP\n";
        return false;
    }

    return transformGEP(GEP);
}

bool ConstantTimeTransformer::transformGEP(
    llvm::GetElementPtrInst *GEP) {

    if (!GEP) {
        return false;
    }

    llvm::errs()
        << "TRANSFORMER: GEP found\n";

    llvm::LoadInst *LI = nullptr;

    for (llvm::User *User : GEP->users()) {
        if (auto *Load =
                llvm::dyn_cast<llvm::LoadInst>(User)) {

            if (LI) {
                llvm::errs()
                    << "TRANSFORMER: Multiple loads use GEP\n";
                return false;
            }

            LI = Load;
        }
    }

    if (!LI) {
        llvm::errs()
            << "TRANSFORMER: Load not found\n";
        return false;
    }

    llvm::errs()
        << "TRANSFORMER: Load found\n";

    llvm::Value *Base =
        GEP->getPointerOperand();

    auto *GV =
        llvm::dyn_cast<llvm::GlobalVariable>(Base);

    if (!GV) {
        llvm::errs()
            << "TRANSFORMER: Base is not a global variable\n";
        return false;
    }

    if (!GV->hasInitializer()) {
        llvm::errs()
            << "TRANSFORMER: Global has no initializer\n";
        return false;
    }

    auto *Array =
        llvm::dyn_cast<llvm::ConstantDataArray>(
            GV->getInitializer());

    if (!Array) {
        llvm::errs()
            << "TRANSFORMER: Global is not a ConstantDataArray\n";
        return false;
    }

    auto *ArrayTy =
        llvm::dyn_cast<llvm::ArrayType>(
            GEP->getSourceElementType());

    if (!ArrayTy) {
        llvm::errs()
            << "TRANSFORMER: GEP source is not an ArrayType\n";
        return false;
    }

    uint64_t NumElements =
        ArrayTy->getNumElements();

    if (NumElements == 0 || NumElements > 256) {
        llvm::errs()
            << "TRANSFORMER: Unsupported array size\n";
        return false;
    }

    if (GEP->getNumIndices() != 2) {
        llvm::errs()
            << "TRANSFORMER: Unsupported GEP index count\n";
        return false;
    }

    auto IndexIt = GEP->idx_begin();
    ++IndexIt;

    llvm::Value *Index =
        IndexIt->get();

    if (!Index) {
        llvm::errs()
            << "TRANSFORMER: Index not found\n";
        return false;
    }

    llvm::errs()
        << "TRANSFORMER: Building constant-time lookup\n";

    llvm::IRBuilder<> Builder(LI);

    llvm::Type *ElementType =
        ArrayTy->getElementType();

    llvm::Value *Result =
        llvm::Constant::getNullValue(
            ElementType);

    for (uint64_t i = 0;
         i < NumElements;
         ++i) {

        llvm::Constant *Element =
            Array->getElementAsConstant(i);

        llvm::Constant *IndexConstant =
            llvm::ConstantInt::get(
                Index->getType(),
                i);

        llvm::Value *Compare =
            Builder.CreateICmpEQ(
                Index,
                IndexConstant,
                "ct.index");

        Result =
            Builder.CreateSelect(
                Compare,
                Element,
                Result,
                "ct.lookup");
    }

    LI->replaceAllUsesWith(Result);

    if (GEP->use_empty()) {
        GEP->eraseFromParent();
    }

    LI->eraseFromParent();

    llvm::errs()
        << "TRANSFORMER: AES table transformed\n";

    return true;
}

}
