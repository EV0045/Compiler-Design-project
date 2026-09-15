#ifndef VIOLATION_DETECTOR_H
#define VIOLATION_DETECTOR_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/raw_ostream.h>

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

// Forward declaration to avoid circular include:
// TaintEngine.h already includes ViolationDetector.h.
namespace ct_pass { class TaintEngine; }

namespace ct_pass {

/**
 * @brief Taint classification matching the project data contract.
 */
enum class TaintLabel {
    PUBLIC = 0,
    SECRET = 1
};

/**
 * @brief Formal violation types for constant-time security analysis.
 */
enum class ViolationType {
    BRANCH_LEAK,   // Control-flow timing leak: secret-dependent branch condition
    MEMORY_LEAK    // Cache-timing leak: secret-dependent address calculation / index
};

/**
 * @brief Representation of a detected constant-time violation site.
 */
struct ViolationSite {
    llvm::Instruction *instruction = nullptr;   // Target violating instruction
    ViolationType type;                         // BRANCH_LEAK or MEMORY_LEAK
    llvm::Value *leakingOperand = nullptr;      // The specific operand carrying the secret taint
    std::string description;                    // Diagnostic explanation
    std::string sourceLocation;                 // Source file, line, and column if debug info exists

    std::string toString() const;
    void dump() const;
};

/**
 * @brief Shared contract: PropagatedTaintMap provided by Member 3 (TaintEngine)
 * Maps LLVM values (or instruction results) to their computed secrecy label.
 */
using TaintMap = std::unordered_map<const llvm::Value*, TaintLabel>;

/**
 * @brief Member 2 (Thurya) - Violation Detector & Static Verifier
 *
 * Week 1 Deliverable (complete):
 *   - Instruction inspector to isolate and list target 'br' and 'load'/'store'/'gep'
 *     instructions across Basic Blocks.
 *
 * Week 2 Deliverable (complete):
 *   - detectViolations() connected to Member 3 TaintEngine output.
 *   - Convenience overloads accepting TaintEngine& directly.
 *   - Generates the formal ViolationSite list for Member 4's Transformer.
 *
 * Week 3 Deliverable:
 *   - Post-transformation static re-verification (verifyZeroLeaks) on
 *     transformed binaries to confirm zero remaining leaks.
 */
class ViolationDetector {
public:
    ViolationDetector() = default;

    /**
     * @brief Week 1 Core Feature:
     * Walk all Basic Blocks in function F and isolate all candidate instructions
     * that could potentially leak timing information (conditional branches, loads, stores, GEPs).
     */
    std::vector<llvm::Instruction*> isolateCandidateInstructions(llvm::Function &F);

    /**
     * @brief Analyze a Function and detect all constant-time violations using the taint map.
     * @param F The LLVM Function to inspect.
     * @param taintMap Map of values to secrecy labels.
     * @return List of detected ViolationSite structures.
     */
    std::vector<ViolationSite> detectViolations(llvm::Function &F, const TaintMap &taintMap);

    /**
     * @brief Analyze all non-declaration functions in a Module.
     */
    std::vector<ViolationSite> detectViolations(llvm::Module &M, const TaintMap &taintMap);

    /**
     * @brief Week 2 Integration: Convenience overload accepting TaintEngine directly.
     * Extracts the propagated TaintMap from the engine and runs detectViolations.
     * @param F The LLVM Function to inspect.
     * @param engine The fully-analyzed TaintEngine from Member 3.
     * @return List of detected ViolationSite structures.
     */
    std::vector<ViolationSite> detectViolations(llvm::Function &F, const TaintEngine &engine);

    /**
     * @brief Week 2 Integration: Module-level overload accepting TaintEngine directly.
     */
    std::vector<ViolationSite> detectViolations(llvm::Module &M, const TaintEngine &engine);

    /**
     * @brief Inspect a branch instruction.
     * Flags conditional branches whose condition is tainted as SECRET.
     */
    bool inspectBranch(llvm::BranchInst *BI, const TaintMap &taintMap, ViolationSite &outSite);

    /**
     * @brief Inspect a memory access instruction (LoadInst or StoreInst).
     * Flags memory accesses whose pointer/address operand is tainted as SECRET.
     */
    bool inspectMemory(llvm::Instruction *I, const TaintMap &taintMap, ViolationSite &outSite);

    /**
     * @brief Inspect a GetElementPtr (GEP) instruction.
     * Flags address calculations where any index operand is tainted as SECRET.
     */
    bool inspectGEP(llvm::GetElementPtrInst *GEP, const TaintMap &taintMap, ViolationSite &outSite);

    /**
     * @brief Query whether a given LLVM Value is tainted as SECRET in the taint map.
     */
    bool isSecret(const llvm::Value *val, const TaintMap &taintMap) const;

    /**
     * @brief Post-transformation verification check.
     * Re-scans the function to verify zero remaining violations.
     * @param F Transformed function.
     * @param taintMap Updated taint map.
     * @param remainingLeaks Output vector to collect any remaining leaks.
     * @return true if 0 leaks exist (pass verification), false otherwise.
     */
    bool verifyZeroLeaks(llvm::Function &F, const TaintMap &taintMap,
                         std::vector<ViolationSite> &remainingLeaks);

    /**
     * @brief Week 2 Integration: verifyZeroLeaks overload accepting TaintEngine directly.
     */
    bool verifyZeroLeaks(llvm::Function &F, const TaintEngine &engine,
                         std::vector<ViolationSite> &remainingLeaks);

private:
    std::string extractSourceLocation(const llvm::Instruction *I) const;
};

} // namespace ct_pass

#endif // VIOLATION_DETECTOR_H
