#ifndef LLVM_BPFCOV_H
#define LLVM_BPFCOV_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

struct BPFCov : public llvm::PassInfoMixin<BPFCov>
{
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);

    static bool isRequired() { return true; }

    bool runOnModule(llvm::Module &M);
    bool runOnFunction(llvm::Function &F, llvm::Module &M);
    // virtual bool runOnBasicBlock(BasicBlock &BB, Module &M);
};

//------------------------------------------------------------------------------
// Legacy PM interface
//------------------------------------------------------------------------------
// struct LegacyBPFCov : public llvm::ModulePass {

//   static char ID;
//   LegacyBPFCov() : llvm::ModulePass(ID) {}
//   bool runOnModule(llvm::Module &M) override;

//   void print(llvm::raw_ostream &OutS, llvm::Module const *M) const override;

//   BPFCov Impl;
// };

#endif // LLVM_BPFCOV_H