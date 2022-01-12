#ifndef LLVM_BPFCOV_H
#define LLVM_BPFCOV_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

//------------------------------------------------------------------------------
// New PM / Interface
//------------------------------------------------------------------------------
struct BPFCov : public llvm::PassInfoMixin<BPFCov>
{
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);

    static bool isRequired() { return true; }

    virtual bool runOnModule(llvm::Module &M);
};

//------------------------------------------------------------------------------
// Legacy PM / Interface
//------------------------------------------------------------------------------
struct LegacyBPFCov : public llvm::ModulePass
{
    static char ID;
    LegacyBPFCov() : llvm::ModulePass(ID) {}
    bool runOnModule(llvm::Module &M) override;
    void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
    void print(llvm::raw_ostream &OutS, llvm::Module const *M) const override;

    BPFCov Impl;
};

#endif // LLVM_BPFCOV_H