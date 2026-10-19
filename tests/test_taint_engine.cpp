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

    std::cout << "Member 3 TaintEngine test: PASS\n";
    return 0;
}
