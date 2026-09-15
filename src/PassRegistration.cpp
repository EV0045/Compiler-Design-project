#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

namespace
{

struct ConstantTimePass : PassInfoMixin<ConstantTimePass>
{
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM)
    {
        return PreservedAnalyses::all();
    }
};

}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
    return {
        LLVM_PLUGIN_API_VERSION,
        "ConstantTimePass",
        LLVM_VERSION_STRING,
        [](PassBuilder &PB)
        {
            PB.registerPipelineParsingCallback(
                [](StringRef Name,
                   ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>)
                {
                    if (Name == "constant-time-pass")
                    {
                        MPM.addPass(ConstantTimePass());
                        return true;
                    }

                    return false;
                });
        }
    };
}

