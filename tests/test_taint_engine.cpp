#include "TaintEngine.h"
#include "ViolationDetector.h"
#include <cassert>
#include <iostream>
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

int main() {
    llvm::LLVMContext context;
    llvm::Module module("taint_engine_test", context);
    llvm::IRBuilder<> builder(context);
    auto *intType = llvm::Type::getInt32Ty(context);
    auto *functionType = llvm::FunctionType::get(intType, {intType, intType}, false);
    auto *function = llvm::Function::Create(functionType, llvm::Function::ExternalLinkage, "test_taint", module);
    auto it = function->arg_begin();
    llvm::Argument *secretArg = &*it++;
    llvm::Argument *publicArg = &*it;
    secretArg->setName("secret");
    publicArg->setName("public");
    llvm::BasicBlock *entry = llvm::BasicBlock::Create(context, "entry", function);
    builder.SetInsertPoint(entry);

    auto *sum = builder.CreateAdd(secretArg, publicArg, "sum");
    auto *cmp = builder.CreateICmpEQ(sum, llvm::ConstantInt::get(intType, 0), "cmp");
    auto *slot = builder.CreateAlloca(intType, nullptr, "slot");
    builder.CreateStore(secretArg, slot);
    auto *loaded = builder.CreateLoad(intType, slot, "loaded");
    builder.CreateRet(builder.CreateSelect(cmp, loaded, publicArg, "result"));

    ct_pass::TaintEngine engine;
    ct_pass::TaintEngine::InitialLabels labels;
    labels[secretArg] = SecrecyLabel::SECRET;
    labels[publicArg] = SecrecyLabel::PUBLIC;
    engine.initialize(labels);
    engine.analyze(*function);

    assert(engine.isSecret(secretArg));
    assert(!engine.isSecret(publicArg));
    assert(engine.isSecret(sum));
    assert(engine.isSecret(cmp));
    assert(engine.isSecret(loaded));

    ct_pass::ViolationDetector detector;
    auto violations = detector.detectViolations(*function, engine.getTaintMap());
    assert(violations.empty());

<<<<<<< Updated upstream
=======
    // Behavioural case: a secret branch selecting two PUBLIC constants must
    // taint the join phi through implicit-flow/control dependence.
    auto *branchTy = llvm::FunctionType::get(intType, {llvm::Type::getInt1Ty(context)}, false);
    auto *branchFn = llvm::Function::Create(branchTy, llvm::Function::ExternalLinkage, "secret_branch_phi", module);
    auto *secretCond = &*branchFn->arg_begin();
    secretCond->setName("secret_cond");
    auto *bEntry = llvm::BasicBlock::Create(context, "entry", branchFn);
    auto *bThen = llvm::BasicBlock::Create(context, "then", branchFn);
    auto *bElse = llvm::BasicBlock::Create(context, "else", branchFn);
    auto *bJoin = llvm::BasicBlock::Create(context, "join", branchFn);
    builder.SetInsertPoint(bEntry);
    builder.CreateCondBr(secretCond, bThen, bElse);
    builder.SetInsertPoint(bThen);
    builder.CreateBr(bJoin);
    builder.SetInsertPoint(bElse);
    builder.CreateBr(bJoin);
    builder.SetInsertPoint(bJoin);
    auto *branchPhi = builder.CreatePHI(intType, 2, "selected");
    branchPhi->addIncoming(llvm::ConstantInt::get(intType, 7), bThen);
    branchPhi->addIncoming(llvm::ConstantInt::get(intType, 9), bElse);
    builder.CreateRet(branchPhi);
    ct_pass::TaintEngine branchEngine;
    ct_pass::TaintEngine::InitialLabels branchLabels;
    branchLabels[secretCond] = SecrecyLabel::SECRET;
    branchEngine.initialize(branchLabels);
    branchEngine.analyze(*branchFn);
    assert(branchEngine.isSecret(branchPhi));
    assert(branchEngine.getIterationCount() > 0 && branchEngine.getIterationCount() < 100);

    // Secret pointer argument means secret pointee contents, not secret address.
    auto *ptrTy = llvm::PointerType::getUnqual(intType);
    auto *loadFnTy = llvm::FunctionType::get(intType, {ptrTy}, false);
    auto *loadFn = llvm::Function::Create(loadFnTy, llvm::Function::ExternalLinkage, "secret_pointer_contents", module);
    auto *secretPtr = &*loadFn->arg_begin();
    secretPtr->setName("secret_ptr");
    auto *loadEntry = llvm::BasicBlock::Create(context, "entry", loadFn);
    builder.SetInsertPoint(loadEntry);
    auto *pointerLoad = builder.CreateLoad(intType, secretPtr, "loaded_secret");
    builder.CreateRet(pointerLoad);
    ct_pass::TaintEngine pointerEngine;
    ct_pass::TaintEngine::InitialLabels pointerLabels;
    pointerLabels[secretPtr] = SecrecyLabel::SECRET;
    pointerEngine.initialize(pointerLabels);
    pointerEngine.analyze(*loadFn);
    assert(!pointerEngine.isSecret(secretPtr));
    assert(pointerEngine.isSecret(pointerLoad));
    assert(pointerEngine.getIterationCount() > 0 && pointerEngine.getIterationCount() < 100);

    // Secret index must taint the GEP address; a call with a secret scalar
    // argument must taint its returned value.
    auto *gepFnTy = llvm::FunctionType::get(intType, {ptrTy, intType}, false);
    auto *gepFn = llvm::Function::Create(gepFnTy, llvm::Function::ExternalLinkage, "secret_index_gep", module);
    auto gepArg = gepFn->arg_begin();
    llvm::Argument *arrayPtr = &*gepArg++;
    llvm::Argument *secretIndex = &*gepArg;
    arrayPtr->setName("array"); secretIndex->setName("secret_index");
    auto *gepEntry = llvm::BasicBlock::Create(context, "entry", gepFn);
    builder.SetInsertPoint(gepEntry);
    auto *elementPtr = builder.CreateGEP(intType, arrayPtr, secretIndex, "element_ptr");
    auto *element = builder.CreateLoad(intType, elementPtr, "element");
    builder.CreateRet(element);
    ct_pass::TaintEngine gepEngine;
    ct_pass::TaintEngine::InitialLabels gepLabels;
    gepLabels[secretIndex] = SecrecyLabel::SECRET;
    gepEngine.initialize(gepLabels); gepEngine.analyze(*gepFn);
    assert(gepEngine.isSecret(elementPtr));

    auto *calleeTy = llvm::FunctionType::get(intType, {intType}, false);
    auto *callee = llvm::Function::Create(calleeTy, llvm::Function::ExternalLinkage, "opaque_call", module);
    auto *calleeEntry = llvm::BasicBlock::Create(context, "entry", callee);
    builder.SetInsertPoint(calleeEntry); builder.CreateRet(&*callee->arg_begin());
    auto *callFn = llvm::Function::Create(calleeTy, llvm::Function::ExternalLinkage, "secret_call_arg", module);
    auto *callArg = &*callFn->arg_begin(); callArg->setName("secret_call_input");
    auto *callEntry = llvm::BasicBlock::Create(context, "entry", callFn);
    builder.SetInsertPoint(callEntry);
    auto *callResult = builder.CreateCall(callee, {callArg}, "call_result");
    builder.CreateRet(callResult);
    ct_pass::TaintEngine callEngine;
    ct_pass::TaintEngine::InitialLabels callLabels;
    callLabels[callArg] = SecrecyLabel::SECRET;
    callEngine.initialize(callLabels); callEngine.analyze(*callFn);
    assert(callEngine.isSecret(callResult));
    assert(callEngine.getIterationCount() > 0 && callEngine.getIterationCount() < 100);

>>>>>>> Stashed changes
    std::cout << "Member 3 TaintEngine test: PASS\n";
    return 0;
}
