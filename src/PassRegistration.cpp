#include "ConstantTimeTransformer.h"
#include "SecrecyLabeller.h"
#include "TaintEngine.h"
#include "ViolationDetector.h"

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#if __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

static cl::opt<std::string> CTConfig(
    "ct-config",
    cl::desc("Path to constant-time secrecy configuration JSON"),
    cl::init(""));

namespace
{

struct ConstantTimePass : PassInfoMixin<ConstantTimePass>
{
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM)
    {
        if (CTConfig.empty()) {
            errs() << "Error: -ct-config is required\n";
            return PreservedAnalyses::all();
        }

        SecrecyLabeller labeller;

        if (!labeller.loadConfig(CTConfig)) {
            errs() << "Error: failed to load config: "
                   << CTConfig << "\n";
            return PreservedAnalyses::all();
        }

        ct_pass::TaintEngine engine;

        for (Function &F : M) {
            if (F.isDeclaration()) {
                continue;
            }

            auto initialLabels = labeller.labelFunction(F);

            engine.initialize(initialLabels);
            engine.analyze(F);
                        ct_pass::ViolationDetector detector;

            auto violations = detector.detectViolations(F, engine);

            if (violations.empty()) {
                continue;
            }

            ct_pass::ConstantTimeTransformer transformer;

            bool changed = transformer.transformFunction(F, violations);

            if (changed) {
                engine.initialize(initialLabels);
                engine.analyze(F);

                std::vector<ct_pass::ViolationSite> remainingLeaks;

                bool verified = detector.verifyZeroLeaks(
                    F, engine, remainingLeaks);

                if (!verified) {
                    errs() << "CT verification failed for function: "
                           << F.getName() << "\n";

                    for (const auto &leak : remainingLeaks) {
                        leak.dump();
                    }
                } else {
                    errs() << "CT verification passed for function: "
                           << F.getName() << "\n";
                }
            } else {
                errs() << "CT transformation made no changes for function: "
                       << F.getName() << "\n";
            }

        }

        return PreservedAnalyses::none();
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
                    if (Name == "constant-time-pass") {
                        MPM.addPass(ConstantTimePass());
                        return true;
                    }

                    return false;
                });
        }
    };
}

