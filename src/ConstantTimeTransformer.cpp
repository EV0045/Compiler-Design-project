
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

    llvm::BasicBlock *Parent = BI->getParent();
    llvm::BasicBlock *Succ0 = BI->getSuccessor(0);
    llvm::BasicBlock *Succ1 = BI->getSuccessor(1);

    if (!Succ0 || !Succ1 || Succ0 == Succ1) {
        return false;
    }

    llvm::BasicBlock *ThenBlock = nullptr;
    llvm::BasicBlock *ElseBlock = nullptr;
    llvm::BasicBlock *MergeBlock = nullptr;
    llvm::BranchInst *ThenBranch = nullptr;
    llvm::BranchInst *ElseBranch = nullptr;
    bool IsTriangle = false;

    auto *Succ0Branch =
        llvm::dyn_cast<llvm::BranchInst>(Succ0->getTerminator());
    auto *Succ1Branch =
        llvm::dyn_cast<llvm::BranchInst>(Succ1->getTerminator());

    if (Succ0Branch && !Succ0Branch->isConditional() &&
        Succ0Branch->getSuccessor(0) == Succ1) {
        ThenBlock = Succ0;
        MergeBlock = Succ1;
        ThenBranch = Succ0Branch;
        IsTriangle = true;
    } else if (Succ1Branch && !Succ1Branch->isConditional() &&
               Succ1Branch->getSuccessor(0) == Succ0) {
        ThenBlock = Succ1;
        MergeBlock = Succ0;
        ThenBranch = Succ1Branch;
        IsTriangle = true;
    } else {
        if (!Succ0Branch || !Succ1Branch ||
            Succ0Branch->isConditional() ||
            Succ1Branch->isConditional() ||
            Succ0Branch->getSuccessor(0) !=
                Succ1Branch->getSuccessor(0)) {
            return false;
        }

        ThenBlock = Succ0;
        ElseBlock = Succ1;
        ThenBranch = Succ0Branch;
        ElseBranch = Succ1Branch;
        MergeBlock = ThenBranch->getSuccessor(0);
    }

    if (!MergeBlock || MergeBlock == Parent ||
        MergeBlock == ThenBlock) {
        return false;
    }

    llvm::PHINode *Phi = nullptr;

    for (llvm::Instruction &I : *MergeBlock) {
        if (auto *P = llvm::dyn_cast<llvm::PHINode>(&I)) {
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

    llvm::Value *ThenValue =
        Phi->getIncomingValueForBlock(ThenBlock);

    if (!ThenValue) {
        return false;
    }

    llvm::Value *ElseValue = nullptr;

    if (IsTriangle) {
        ElseValue = Phi->getIncomingValueForBlock(Parent);
    } else {
        ElseValue = Phi->getIncomingValueForBlock(ElseBlock);
    }

    if (!ElseValue) {
        return false;
    }

    auto SafeToMove = [](llvm::BasicBlock *Block,
                         llvm::Instruction *Terminator) {
        for (llvm::Instruction &I : *Block) {
            if (&I == Terminator) {
                break;
            }

            if (llvm::isa<llvm::PHINode>(&I) ||
                !llvm::isSafeToSpeculativelyExecute(&I)) {
                return false;
            }
        }
        return true;
    };

    if (!SafeToMove(ThenBlock, ThenBranch)) {
    return false;
    }

    if (!IsTriangle &&
        !SafeToMove(ElseBlock, ElseBranch)) {
        return false;
    }

    llvm::Value *Condition = BI->getCondition();

    if (IsTriangle && ThenBlock == Succ1) {
        Condition = llvm::BinaryOperator::CreateNot(
            Condition, "ct.not", BI);
    }

    for (auto It = ThenBlock->begin();
         It != ThenBranch->getIterator();) {
        llvm::Instruction *I = &*It++;
        I->moveBefore(BI);
    }

    if (!IsTriangle) {
        for (auto It = ElseBlock->begin();
             It != ElseBranch->getIterator();) {
            llvm::Instruction *I = &*It++;
            I->moveBefore(BI);
        }
    }

    auto *Select = llvm::SelectInst::Create(
        Condition, ThenValue, ElseValue, "ct.select", BI);

    Phi->replaceAllUsesWith(Select);
    Phi->eraseFromParent();

    llvm::ReplaceInstWithInst(
        BI, llvm::BranchInst::Create(MergeBlock));

    ThenBranch->eraseFromParent();

    if (!IsTriangle) {
        ElseBranch->eraseFromParent();
        ElseBlock->removeFromParent();
        delete ElseBlock;
    }

    ThenBlock->removeFromParent();
    delete ThenBlock;

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
        << "TRANSFORMER: Building mask-based lookup\n";

    llvm::IRBuilder<> Builder(LI);

    llvm::Type *ElementType =
        ArrayTy->getElementType();

    if (!ElementType->isIntegerTy()) {
        llvm::errs()
            << "TRANSFORMER: Unsupported non-integer table element\n";
        return false;
    }

    llvm::Value *Result =
        llvm::Constant::getNullValue(ElementType);

    for (uint64_t i = 0;
         i < NumElements;
         ++i) {

        llvm::Constant *Element =
            Array->getElementAsConstant(i);

        if (Element->getType() != ElementType) {
            llvm::errs()
                << "TRANSFORMER: Table element type mismatch\n";
            return false;
        }

        llvm::Constant *IndexConstant =
            llvm::ConstantInt::get(
                Index->getType(),
                i);

        llvm::Value *Compare =
            Builder.CreateICmpEQ(
                Index,
                IndexConstant,
                "ct.index");

        llvm::Value *Mask =
            Builder.CreateSExt(
                Compare,
                ElementType,
                "ct.mask");

        llvm::Value *MaskedElement =
            Builder.CreateAnd(
                Mask,
                Element,
                "ct.masked");

        Result =
            Builder.CreateOr(
                Result,
                MaskedElement,
                "ct.lookup");
    }
    LI->replaceAllUsesWith(Result);
    LI->eraseFromParent();

    if (GEP->use_empty()) {
       GEP->eraseFromParent();
     }

    llvm::errs()
        << "TRANSFORMER: AES table transformed\n";

    return true;
}

}
