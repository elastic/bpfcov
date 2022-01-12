//=====================================================================================================================
// FILE:
//    BPFCov.cpp
//
// AUTHOR:
//    Leonardo Di Donato (leodido)
//
// DESCRIPTION:
//    Patch the IR of eBPF programs instrumented for source-code based coverage (-fprofile-instr-generate -fcoverage-mapping).
//
// USAGE:
//    1. Legacy LLVM Pass Manager
//        opt --load libBPFCov.{so,dylib} [--strip-initializers-only] --bpf-cov <input>
//
//    2. New LLVM Pass Manager
//        opt --load-pass-plugin libBPFCov.{so,dylib} --passes='bpf-cov' <input>
//
//        OR
//
//        opt --load-pass-plugin libBPFCov.{so,dylib} --passes='default<O2>' <input>
//
//        NOTICE: CLI options not available when using the new Pass Manager.
//
// LICENSE:
//    ...
//=====================================================================================================================
#include "BPFCov.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/PassRegistry.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Support/CommandLine.h"

static constexpr char PassArg[] = "bpf-cov";
static constexpr char PassName[] = "BPF Coverage Pass";
static constexpr char PluginName[] = "BPFCov";

#define DEBUG_TYPE ::PassArg

// NOTE > LLVM_DEBUG requires a LLVM built with NDEBUG unset
// NOTE > Then use with opt -debug

using namespace llvm;

//---------------------------------------------------------------------------------------------------------------------
// CLI options
//---------------------------------------------------------------------------------------------------------------------

// This cause the resulting BPF ELF to be readable by llvm-cov for coverage output,
// but it does not output a valid BPF program.
static cl::opt<bool>
    StripInitializersOnly(
        "strip-initializers-only",
        cl::desc("Stop the pass after the initializers have been removed"),
        cl::init(false));

//---------------------------------------------------------------------------------------------------------------------
// Utility functions
//---------------------------------------------------------------------------------------------------------------------

namespace
{

    bool deleteGVarByName(Module &M, StringRef Name)
    {
        auto GV = M.getNamedGlobal(Name);
        if (!GV)
        {
            return false;
        }
        errs() << "erasing " << Name << "\n";
        GV->eraseFromParent();
        return true;
    }

    bool deleteFuncByName(Module &M, StringRef Name)
    {
        auto F = M.getFunction(Name);
        if (!F)
        {
            return false;
        }
        errs() << "erasing " << Name << "()\n";
        F->replaceAllUsesWith(UndefValue::get(F->getType()));
        F->eraseFromParent();

        return true;
    }

    bool fixupUsedGlobals(Module &M)
    {
        auto U = M.getNamedGlobal("llvm.used");
        if (!U || !U->hasInitializer())
        {
            return false;
        }

        SmallVector<Constant *, 8> UsedGlobals;
        auto UArray = dyn_cast<ConstantArray>(U->getInitializer());
        auto NElems = UArray->getNumOperands();
        for (unsigned int i = 0; i < NElems; i++)
        {
            if (ConstantExpr *CE = dyn_cast<ConstantExpr>(UArray->getOperand(i)))
            {
                auto OC = CE->getOpcode();
                if (OC == Instruction::BitCast || OC == Instruction::GetElementPtr)
                {
                    if (GlobalValue *GV = dyn_cast<GlobalValue>(CE->getOperand(0)))
                    {
                        auto Name = GV->getName();
                        if (!Name.startswith("__llvm_profile_runtime") && !Name.startswith("__profd") && !Name.startswith("__covrec") && !Name.startswith("__llvm_coverage"))
                        {
                            UsedGlobals.push_back(UArray->getOperand(i));
                        }
                    }
                }
            }
            // TODO(leodido) > almost certainly the following doesn't make sense for "llvm.used" array
            else if (GlobalValue *GV = dyn_cast<GlobalValue>(UArray->getOperand(i)))
            {
                auto Name = GV->getName();
                if (!Name.startswith("__llvm_profile_runtime") && !Name.startswith("__profd") && !Name.startswith("__covrec") && !Name.startswith("__llvm_coverage"))
                {
                    UsedGlobals.push_back(UArray->getOperand(i));
                }
            }
        }

        if (UsedGlobals.size() < NElems)
        {
            errs() << "fixing llvm.used\n";
            U->eraseFromParent();
            ArrayType *AType = ArrayType::get(Type::getInt8PtrTy(M.getContext()), UsedGlobals.size());
            U = new GlobalVariable(M, AType, false, GlobalValue::AppendingLinkage, ConstantArray::get(AType, UsedGlobals), "llvm.used");
            U->setSection("llvm.metadata");

            return true;
        }

        return false;
    }

    bool swapSectionWithPrefix(Module &M, StringRef Prefix, StringRef New)
    {
        bool Changed = false;
        for (auto gv_iter = M.global_begin(); gv_iter != M.global_end(); gv_iter++)
        {
            GlobalVariable *GV = &*gv_iter;
            if (GV->hasSection() && GV->getSection().startswith(Prefix))
            {
                errs() << "swapping " << GV->getName() << " section with " << New << " \n";
                GV->setSection(New);
                Changed = true;
            }
        }
        return Changed;
    }

    bool convertStructs(Module &M)
    {
        bool Changed = false;

        auto &CTX = M.getContext();
        SmallVector<GlobalVariable *, 8> ToDelete;
        auto CountersSizeAcc = 0;

        for (auto gv_iter = M.global_begin(); gv_iter != M.global_end(); gv_iter++)
        {
            GlobalVariable *GV = &*gv_iter;
            if (GV->hasName())
            {
                auto Name = GV->getName();
                if (Name.startswith("__profd") && GV->getValueType()->isStructTy())
                {
                    errs() << "converting " << Name << " struct to globals\n";

                    // Translate the function ID to a global scalar
                    ConstantInt *C0 = dyn_cast<ConstantInt>(GV->getInitializer()->getOperand(0));
                    if (!C0)
                    {
                        // TODO(leodido) > bail out
                        errs() << Name << ": cast failed\n";
                    }
                    auto Ty = C0->getType();
                    if (!Ty->isIntegerTy(64))
                    {
                        // TODO(leodido) > bail out
                        errs() << Name << ": wrong type bandwidth\n";
                    }
                    auto *GV0 = new GlobalVariable(
                        M,
                        /*Ty=*/Ty,
                        /*isConstant=*/true,
                        /*Linkage=*/GlobalVariable::ExternalLinkage,
                        /*Initializer=*/ConstantInt::get(Ty, C0->getSExtValue(), true),
                        /*Name=*/Name + ".0",
                        /*InsertBefore=*/GV);
                    GV0->setDSOLocal(true);
                    GV0->setAlignment(MaybeAlign(8));
                    GV0->setSection(GV->getSection());

                    appendToUsed(M, GV0);

                    Changed = true;

                    // Translate the function hash to a global scalar
                    ConstantInt *C1 = dyn_cast<ConstantInt>(GV->getInitializer()->getOperand(1));
                    if (!C1)
                    {
                        // TODO(leodido) > bail out
                        errs() << Name << ": cast failed\n";
                    }
                    auto Ty1 = C1->getType();
                    if (!Ty1->isIntegerTy(64))
                    {
                        // TODO(leodido) > bail out
                        errs() << Name << ": wrong type bandwidth\n";
                    }
                    auto *GV1 = new GlobalVariable(
                        M,
                        /*Ty=*/Ty1,
                        /*isConstant=*/true,
                        /*Linkage=*/GlobalVariable::ExternalLinkage,
                        /*Initializer=*/ConstantInt::get(Ty1, C1->getSExtValue(), true),
                        /*Name=*/Name + ".1",
                        /*InsertBefore=*/GV);
                    GV1->setDSOLocal(true);
                    GV1->setAlignment(MaybeAlign(8));
                    GV1->setSection(GV->getSection());

                    appendToUsed(M, GV1);

                    // Get the number of counters for current __profd_*
                    ConstantInt *C5 = dyn_cast<ConstantInt>(GV->getInitializer()->getOperand(5));
                    if (!C5)
                    {
                        // TODO(leodido) > bail out
                        errs() << Name << ": cast failed\n";
                    }
                    auto Ty5 = C5->getType();
                    if (!Ty5->isIntegerTy(32))
                    {
                        // TODO(leodido) > bail out
                        errs() << Name << ": wrong type bandwidth\n";
                    }

                    auto NumCounters = C5->getSExtValue();

                    // Translate the address of the counter to a global scalar containing the relative offset
                    auto *GV2 = new GlobalVariable(
                        M,
                        /*Ty=*/Ty1,
                        /*isConstant=*/true,
                        /*Linkage=*/GlobalVariable::ExternalLinkage,
                        /*Initializer=*/ConstantInt::get(Ty1, CountersSizeAcc, true),
                        /*Name=*/Name + ".2",
                        /*InsertBefore=*/GV);
                    GV2->setDSOLocal(true);
                    GV2->setAlignment(MaybeAlign(8));
                    GV2->setSection(GV->getSection());
                    appendToUsed(M, GV2);

                    // Increment the counter offset for the next __profd_*
                    CountersSizeAcc += NumCounters * 8;

                    // Create fake (zero) global scalars for 4th and 5th field of __profd_* structs
                    auto *GV3 = new GlobalVariable(
                        M,
                        /*Ty=*/Ty1,
                        /*isConstant=*/true,
                        /*Linkage=*/GlobalVariable::ExternalLinkage,
                        /*Initializer=*/ConstantInt::get(Ty1, 0, true), // TODO > we want this or zeroinitializer?
                        /*Name=*/Name + ".3",
                        /*InsertBefore=*/GV);
                    GV3->setDSOLocal(true);
                    GV3->setAlignment(MaybeAlign(8));
                    GV3->setSection(GV->getSection());
                    appendToUsed(M, GV3);

                    auto *GV4 = new GlobalVariable(
                        M,
                        /*Ty=*/Ty1,
                        /*isConstant=*/true,
                        /*Linkage=*/GlobalVariable::ExternalLinkage,
                        /*Initializer=*/ConstantInt::get(Ty1, 0, true), // TODO > we want this or zeroinitializer?
                        /*Name=*/Name + ".4",
                        /*InsertBefore=*/GV);
                    GV4->setDSOLocal(true);
                    GV4->setAlignment(MaybeAlign(8));
                    GV4->setSection(GV->getSection());
                    appendToUsed(M, GV4);

                    // Translate the number of counters (that this data refers to) to a global scalar
                    auto NumCountersC = ConstantInt::get(Ty5, NumCounters, true);
                    auto *GV5 = new GlobalVariable(
                        M,
                        /*Ty=*/Ty5,
                        /*isConstant=*/true,
                        /*Linkage=*/GlobalVariable::ExternalLinkage,
                        /*Initializer=*/NumCountersC,
                        /*Name=*/Name + ".5",
                        /*InsertBefore=*/GV);
                    GV5->setDSOLocal(true);
                    GV5->setAlignment(MaybeAlign(4));
                    GV5->setSection(GV->getSection());
                    appendToUsed(M, GV5);

                    // Translate the value sites [2 x i16] into a single i32
                    auto *GV6 = new GlobalVariable(
                        M,
                        /*Ty=*/Ty5,
                        /*isConstant=*/true,
                        /*Linkage=*/GlobalVariable::ExternalLinkage,
                        /*Initializer=*/ConstantInt::get(Ty5, 0, true), // TODO > obtain from the array values
                        /*Name=*/Name + ".6",
                        /*InsertBefore=*/GV);
                    GV6->setDSOLocal(true);
                    GV6->setAlignment(MaybeAlign(4));
                    GV6->setSection(GV->getSection());
                    appendToUsed(M, GV6);

                    ToDelete.push_back(GV);
                }
                else if (Name.startswith("__covrec") && GV->getValueType()->isStructTy())
                {
                    ToDelete.push_back(GV);
                }
                else if (Name.startswith("__llvm_coverage") && GV->getValueType()->isStructTy())
                {
                    errs() << "converting " << Name << " struct to globals\n";

                    ConstantStruct *C0 = dyn_cast<ConstantStruct>(GV->getInitializer()->getOperand(0));
                    if (!C0)
                    {
                        // TODO(leodido) > bail out
                        errs() << Name << ": cast failed\n";
                    }
                    auto Ty0 = C0->getType();
                    if (!Ty0->isStructTy())
                    {
                        // TODO(leodido) > bail out
                        errs() << Name << ": wrong type\n";
                    }

                    SmallVector<Constant *, 8> Vals;
                    for (unsigned int i = 0; i < C0->getNumOperands(); i++)
                    {
                        ConstantInt *C = dyn_cast<ConstantInt>(C0->getOperand(i));
                        if (!C)
                        {
                            // TODO(leodido) > bail out
                            errs() << Name << ": cast failed\n";
                        }
                        if (!C->getType()->isIntegerTy(32))
                        {
                            // TODO(leodido) > bail out
                            errs() << Name << ": wrong type\n";
                        }
                        Vals.push_back(C);
                    }

                    ArrayType *ATy = ArrayType::get(Type::getInt32Ty(CTX), Vals.size());

                    auto *GV0 = new GlobalVariable(
                        M,
                        /*Ty=*/ATy,
                        /*isConstant=*/true,
                        /*Linkage=*/GlobalVariable::ExternalLinkage,
                        /*Initializer=*/ConstantArray::get(ATy, Vals),
                        /*Name=*/Name + ".0",
                        /*InsertBefore=*/GV);
                    GV0->setDSOLocal(true);
                    GV0->setSection(GV->getSection());
                    GV0->setAlignment(MaybeAlign(4));

                    Changed = true;

                    appendToUsed(M, GV0);

                    ConstantDataArray *C1 = dyn_cast<ConstantDataArray>(GV->getInitializer()->getOperand(1));
                    if (!C1)
                    {
                        // TODO(leodido) > bail out
                        errs() << Name << ": cast failed\n";
                    }
                    auto Ty1 = C1->getType();
                    if (!Ty1->isArrayTy())
                    {
                        // TODO(leodido) > bail out
                        errs() << Name << ": wrong type\n";
                    }

                    auto *GV1 = new GlobalVariable(
                        M,
                        /*Ty=*/Ty1,
                        /*isConstant=*/true,
                        /*Linkage=*/GlobalVariable::ExternalLinkage,
                        /*Initializer=*/ConstantDataArray::getString(CTX, C1->getRawDataValues(), false),
                        /*Name=*/Name + ".1",
                        /*InsertBefore=*/GV);
                    GV1->setDSOLocal(true);
                    GV1->setAlignment(MaybeAlign(1));
                    GV1->setSection(GV->getSection());

                    appendToUsed(M, GV1);

                    ToDelete.push_back(GV);
                }
            }
        }

        for (auto *GV : ToDelete)
        {
            errs() << "erasing " << GV->getName() << "\n";
            GV->eraseFromParent();
        }

        return Changed;
    }

    bool annotateCounters(Module &M)
    {
        bool Annotated = false;

        DIBuilder DIB(M);

        Module::debug_compile_units_iterator CUIterator = M.debug_compile_units_begin();
        auto *DebugCU = *CUIterator;
        auto *DebugFile = DebugCU->getFile();

        // Save the current list of globals from the CU debug info
        SmallVector<Metadata *> DebugGlobals;
        for (auto *DG : DebugCU->getGlobalVariables())
        {
            DebugGlobals.push_back(DG);
        }

        for (auto gv_iter = M.global_begin(); gv_iter != M.global_end(); gv_iter++)
        {
            GlobalVariable *GV = &*gv_iter;
            if (GV->hasName())
            {
                if (GV->getName().startswith("__profc") && GV->getValueType()->isArrayTy())
                {
                    // Change to DSO local
                    GV->setLinkage(GlobalValue::LinkageTypes::ExternalLinkage);
                    GV->setDSOLocal(true);

                    auto N = GV->getValueType()->getArrayNumElements();

                    auto *S64Ty = DIB.createBasicType("long long int", 64, dwarf::DW_ATE_signed);

                    auto *DebugArrayTy = DIB.createArrayType(
                        /*Size=*/N * 64,
                        /*AlignInBits=*/0,
                        /*Ty=*/S64Ty,
                        /*Subscripts=*/DIB.getOrCreateArray({DIB.getOrCreateSubrange(0, N)}));

                    auto *DebugGVE = DIB.createGlobalVariableExpression(
                        /*Context=*/DebugCU,
                        /*Name=*/GV->getName(),
                        /*LinkageName=*/"",
                        /*File=*/DebugFile,
                        /*LineNo=*/0,
                        /*Ty=*/DebugArrayTy,
                        /*IsLocalToUnit=*/GV->hasLocalLinkage(),
                        /*IsDefinition=*/true,
                        /*Expr=*/nullptr,
                        /*Decl=*/nullptr,
                        /*TemplateParams=*/nullptr,
                        /*AlignInBits=*/0);

                    GV->addDebugInfo(DebugGVE);
                    DebugGlobals.push_back(DebugGVE);

                    Annotated = true;
                }
                else if (GV->getName() == "__llvm_prf_nm" && GV->getValueType()->isArrayTy())
                {
                    // Change to DSO local
                    GV->setLinkage(GlobalValue::LinkageTypes::ExternalLinkage);
                    GV->setDSOLocal(true);

                    auto N = GV->getValueType()->getArrayNumElements();

                    auto *S8Ty = DIB.createBasicType("char", 8, dwarf::DW_ATE_signed_char);

                    auto *ConstS8Ty = DIB.createQualifiedType(dwarf::DW_TAG_const_type, S8Ty);

                    auto *DebugArrayTy = DIB.createArrayType(
                        /*Size=*/N * 8,
                        /*AlignInBits=*/0,
                        /*Ty=*/ConstS8Ty,
                        /*Subscripts=*/DIB.getOrCreateArray({DIB.getOrCreateSubrange(0, N)}));

                    auto *DebugGVE = DIB.createGlobalVariableExpression(
                        /*Context=*/DebugCU,
                        /*Name=*/GV->getName(),
                        /*LinkageName=*/"",
                        /*File=*/DebugFile,
                        /*LineNo=*/0,
                        /*Ty=*/DebugArrayTy,
                        /*IsLocalToUnit=*/GV->hasLocalLinkage(),
                        /*IsDefinition=*/true,
                        /*Expr=*/nullptr,
                        /*Decl=*/nullptr,
                        /*TemplateParams=*/nullptr,
                        /*AlignInBits=*/0);

                    GV->addDebugInfo(DebugGVE);
                    DebugGlobals.push_back(DebugGVE);

                    Annotated = true;
                }
                else if (GV->getName().startswith("__profd"))
                {
                    DIBasicType *Ty;
                    if (GV->getName().endswith(".0") || GV->getName().endswith(".1") || GV->getName().endswith(".2") || GV->getName().endswith(".3") || GV->getName().endswith(".4"))
                    {
                        Ty = DIB.createBasicType("long long int", 64, dwarf::DW_ATE_signed);
                    }
                    else if (GV->getName().endswith(".5") || GV->getName().endswith(".6"))
                    {
                        Ty = DIB.createBasicType("int", 32, dwarf::DW_ATE_signed);
                    }

                    auto *DebugGVE = DIB.createGlobalVariableExpression(
                        /*Context=*/DebugCU,
                        /*Name=*/GV->getName(),
                        /*LinkageName=*/"",
                        /*File=*/DebugFile,
                        /*LineNo=*/0,
                        /*Ty=*/Ty,
                        /*IsLocalToUnit=*/GV->hasLocalLinkage(),
                        /*IsDefinition=*/true,
                        /*Expr=*/nullptr,
                        /*Decl=*/nullptr,
                        /*TemplateParams=*/nullptr,
                        /*AlignInBits=*/0);

                    GV->addDebugInfo(DebugGVE);
                    DebugGlobals.push_back(DebugGVE);

                    Annotated = true;
                }
                else if (GV->getName().startswith("__covrec"))
                {
                    DIType *GVTy;
                    if (GV->getName().endswith(".0"))
                    {
                        auto *Ty = DIB.createBasicType("long long int", 64, dwarf::DW_ATE_signed);
                        GVTy = DIB.createQualifiedType(dwarf::DW_TAG_const_type, Ty);
                    }
                    if (GV->getName().endswith(".4"))
                    {
                        auto *Ty = DIB.createBasicType("char", 8, dwarf::DW_ATE_signed_char);
                        auto N = GV->getValueType()->getArrayNumElements();
                        GVTy = DIB.createArrayType(
                            /*Size=*/N * 8,
                            /*AlignInBits=*/0,
                            /*Ty=*/DIB.createQualifiedType(dwarf::DW_TAG_const_type, Ty),
                            /*Subscripts=*/DIB.getOrCreateArray({DIB.getOrCreateSubrange(0, N)}));
                    }

                    auto *DebugGVE = DIB.createGlobalVariableExpression(
                        /*Context=*/DebugCU,
                        /*Name=*/GV->getName(),
                        /*LinkageName=*/"",
                        /*File=*/DebugFile,
                        /*LineNo=*/0,
                        /*Ty=*/GVTy,
                        /*IsLocalToUnit=*/GV->hasLocalLinkage(),
                        /*IsDefinition=*/true,
                        /*Expr=*/nullptr,
                        /*Decl=*/nullptr,
                        /*TemplateParams=*/nullptr,
                        /*AlignInBits=*/0);

                    GV->addDebugInfo(DebugGVE);
                    DebugGlobals.push_back(DebugGVE);

                    Annotated = true;
                }
                else if (GV->getName().startswith("__llvm_coverage"))
                {
                    auto N = GV->getValueType()->getArrayNumElements();

                    auto Size = N;
                    DIBasicType *Ty;
                    if (GV->getName().endswith(".0"))
                    {
                        Ty = DIB.createBasicType("int", 32, dwarf::DW_ATE_signed);
                        Size *= 32;
                    }
                    if (GV->getName().endswith(".1"))
                    {
                        Ty = DIB.createBasicType("char", 8, dwarf::DW_ATE_signed_char);
                        Size *= 8;
                    }

                    auto *ConstTy = DIB.createQualifiedType(dwarf::DW_TAG_const_type, Ty);

                    auto *DebugArrayTy = DIB.createArrayType(
                        /*Size=*/Size,
                        /*AlignInBits=*/0,
                        /*Ty=*/ConstTy,
                        /*Subscripts=*/DIB.getOrCreateArray({DIB.getOrCreateSubrange(0, N)}));

                    auto *DebugGVE = DIB.createGlobalVariableExpression(
                        /*Context=*/DebugCU,
                        /*Name=*/GV->getName(),
                        /*LinkageName=*/"",
                        /*File=*/DebugFile,
                        /*LineNo=*/0,
                        /*Ty=*/DebugArrayTy,
                        /*IsLocalToUnit=*/GV->hasLocalLinkage(),
                        /*IsDefinition=*/true,
                        /*Expr=*/nullptr,
                        /*Decl=*/nullptr,
                        /*TemplateParams=*/nullptr,
                        /*AlignInBits=*/0);

                    GV->addDebugInfo(DebugGVE);
                    DebugGlobals.push_back(DebugGVE);

                    Annotated = true;
                }
            }
        }

        if (Annotated)
        {
            errs() << "updating compile unit's globals debug info\n";
            DebugCU->replaceGlobalVariables(MDTuple::get(M.getContext(), DebugGlobals));

            DIB.finalize();
        }

        return Annotated;
    }
}

//---------------------------------------------------------------------------------------------------------------------
// Implementation
//---------------------------------------------------------------------------------------------------------------------

PreservedAnalyses BPFCov::run(Module &M, ModuleAnalysisManager &MAM)
{
    bool changed = runOnModule(M);
    return (changed ? PreservedAnalyses::none() : PreservedAnalyses::all());
}

bool BPFCov::runOnModule(Module &M)
{
    errs() << "module: " << M.getName() << "\n"; // LLVM_DEBUG(dbgs() << "");

    bool instrumented = false;

    // Bail out when missing debug info
    if (M.debug_compile_units().empty())
    {
        errs() << "Missing debug info\n";
        return instrumented;
    }

    // This sequence is not random at all
    instrumented |= deleteGVarByName(M, "llvm.global_ctors");
    instrumented |= deleteFuncByName(M, "__llvm_profile_init");
    instrumented |= deleteFuncByName(M, "__llvm_profile_register_function");
    instrumented |= deleteFuncByName(M, "__llvm_profile_register_names_function");
    instrumented |= deleteFuncByName(M, "__llvm_profile_runtime_user");
    instrumented |= deleteGVarByName(M, "__llvm_profile_runtime");
    instrumented |= fixupUsedGlobals(M);
    // Stop here to avoid rewriting the profiling and coverage structs
    if (StripInitializersOnly)
    {
        return instrumented;
    }
    instrumented |= swapSectionWithPrefix(M, "__llvm_prf_cnts", ".data.profc");
    instrumented |= swapSectionWithPrefix(M, "__llvm_prf_names", ".rodata.profn");
    instrumented |= convertStructs(M);
    instrumented |= annotateCounters(M);
    instrumented |= swapSectionWithPrefix(M, "__llvm_prf_data", ".rodata.profd");
    instrumented |= swapSectionWithPrefix(M, "__llvm_covmap", ".rodata.covmap");

    return instrumented;
}

//---------------------------------------------------------------------------------------------------------------------
// Legacy PM / Implementation
//---------------------------------------------------------------------------------------------------------------------

char LegacyBPFCov::ID = 0;

bool LegacyBPFCov::runOnModule(llvm::Module &M)
{
    if (skipModule(M))
    {
        errs() << "legacy: skipping\n";
        return false;
    }

    errs() << "legacy: running\n";
    return Impl.runOnModule(M);
}

void LegacyBPFCov::print(raw_ostream &OutStream, const Module *) const
{
    OutStream << "BPFCov (Legacy Pass Manager)\n";
}

void LegacyBPFCov::getAnalysisUsage(AnalysisUsage &AU) const
{
    // This pass does not transform the control flow graph
    AU.setPreservesCFG();
}

//---------------------------------------------------------------------------------------------------------------------
// New PM / Registration
//---------------------------------------------------------------------------------------------------------------------
PassPluginLibraryInfo getBPFCovPluginInfo()
{
    return {LLVM_PLUGIN_API_VERSION, PluginName, LLVM_VERSION_STRING,
            [](PassBuilder &PB)
            {
                // #1 Regiser "opt -passes=bpf-cov"
                PB.registerPipelineParsingCallback(
                    [&](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>)
                    {
                        if (Name.equals(PassArg))
                        {
                            errs() << "strip-initializers-only: " << (StripInitializersOnly.getValue() ? "true" : "false") << "\n";
                            MPM.addPass(BPFCov());
                            return true;
                        }
                        return false;
                    });
                // #2 Register for running at "default<O2>" // TODO > double-check
                PB.registerPipelineStartEPCallback(
                    [&](ModulePassManager &MPM, ArrayRef<PassBuilder::OptimizationLevel> OLevels)
                    {
                        if (OLevels.size() == 1 &&
                            OLevels[0] == PassBuilder::OptimizationLevel::O2)
                        {
                            MPM.addPass(BPFCov());
                        }
                    });
            }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
    return getBPFCovPluginInfo();
}

//---------------------------------------------------------------------------------------------------------------------
// Legacy PM / Registration
//---------------------------------------------------------------------------------------------------------------------

static RegisterPass<LegacyBPFCov> X(/*PassArg=*/PassArg,
                                    /*Name=*/PassName,
                                    /*CFGOnly=*/false,
                                    /*is_analysis=*/false);

static RegisterStandardPasses RegisterBPFCov(
    PassManagerBuilder::EP_EarlyAsPossible,
    [](const PassManagerBuilder &, legacy::PassManagerBase &PM)
    {
        errs() << "legacy: strip-initializers-only: " << (StripInitializersOnly.getValue() ? "true" : "false") << "\n";
        PM.add(new LegacyBPFCov());
    });