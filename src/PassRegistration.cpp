#include "ConstantTimeTransformer.h"
#include "SecrecyLabeller.h"
#include "TaintEngine.h"
#include "ViolationDetector.h"

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
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

            auto violations =
                ct_pass::ViolationDetector().detectViolations(F, engine);

            if (violations.empty()) {
                continue;
            }

            ct_pass::ConstantTimeTransformer transformer;
            const bool transformed =
                transformer.transformFunction(F, violations);

            if (transformed) {
                // The transformer may erase phis/instructions. Clear all old
                // value keys and analyse the new IR before verification.
                auto refreshedLabels = labeller.labelFunction(F);
                engine.initialize(refreshedLabels);
                engine.analyze(F);

                std::vector<ct_pass::ViolationSite> remaining;
                ct_pass::ViolationDetector verifier;
                if (!verifier.verifyZeroLeaks(F, engine, remaining)) {
                    errs() << "Post-transform verification: "
                           << remaining.size()
                           << " violation(s) remain in "
                           << F.getName() << "\n";
                    for (const auto &site : remaining)
                        errs() << site.toString();
                } else {
                    errs() << "Post-transform verification: zero detected "
                              "violations in " << F.getName() << "\n";
                }
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

