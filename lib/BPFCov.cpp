//=====================================================================================================================
// FILE:
//    BPFCov.cpp
//
// AUTHOR:
//    Leonardo Di Donato (leodido)
//
// DESCRIPTION:
//    ...
//
//    ...
//
// USAGE:
//    1. Legacy LLVM Pass Manager
//      opt --load libBPFCov.{so,dylib} --bpf-cov <input-llvm-file>
//
//    2. New LLVM Pass Manager
//      opt --load-pass-plugin libBPFCov.{so,dylib} [--stats] --passes='bpf-cov' <input-llvm-file>
//
//      OR
//
//      opt --load-pass-plugin libBPFCov.{so,dylib} [--stats] --passes='default<O2>' <input-llvm-file>
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

static constexpr char PassArg[] = "bpf-cov";
static constexpr char PassName[] = "BPF Coverage Pass";
static constexpr char PluginName[] = "BPFCov";

#define DEBUG_TYPE ::PassArg

// NOTE > LLVM_DEBUG requires a LLVM built with NDEBUG unset
// NOTE > Then use with opt -debug
// TODO > Create unnamed namespace for private functions

using namespace llvm;

std::string Prefix = "bpfcov_";
std::string Suffix = "_map";

//---------------------------------------------------------------------------------------------------------------------
// Utility functions
//---------------------------------------------------------------------------------------------------------------------

Constant *CreateMap(Module &M, StringRef FunctionName)
{
    auto &CTX = M.getContext();
    DIBuilder DIB(M);

    // Define the map struct fields
    auto *MapStructType =
        PointerType::get(ArrayType::get(IntegerType::getInt32Ty(CTX), 1), 0);
    auto *MapStructMaxEntries =
        PointerType::get(ArrayType::get(IntegerType::getInt32Ty(CTX), 8192), 0);
    auto *MapStructKey = IntegerType::getInt64PtrTy(CTX);
    auto *MapStructValue = IntegerType::getInt64PtrTy(CTX);

    // Define the map struct
    std::string StructName = Prefix + FunctionName.str() + Suffix;
    std::string StructTypeName = "struct." + StructName;
    ArrayRef<Type *> MapStructFields = {
        MapStructType,
        MapStructMaxEntries,
        MapStructKey,
        MapStructValue,
    };
    auto *MapStruct = StructType::create(CTX, MapStructFields, StructTypeName);

    // Declarate the map
    std::string MapName = Prefix + std::string(FunctionName);
    Constant *MapVar = M.getOrInsertGlobal(MapName, MapStruct);
    auto *MapGlobal = M.getNamedGlobal(MapName);
    MapGlobal->setDSOLocal(true);
    MapGlobal->setSection(".maps");
    MapGlobal->setAlignment(MaybeAlign(8));
    MapGlobal->setInitializer(Constant::getNullValue(MapStruct));

    // Debug metadata
    Module::debug_compile_units_iterator CUIterator =
        M.debug_compile_units_begin();
    auto *DebugCU = *CUIterator;
    auto *DebugFile = DebugCU->getFile();

    auto *Int = DIB.createBasicType("int", 32, dwarf::DW_ATE_signed);
    auto *LLUInt =
        DIB.createBasicType("long long unsigned int", 64, dwarf::DW_ATE_unsigned);

    // FIXME > how to remove lower bound?
    auto *DebugMapTypeArray = DIB.createArrayType(
        /*Size=*/1 * 32,
        /*AlignInBits=*/0,
        /*Ty=*/Int,
        /*Subscripts=*/DIB.getOrCreateArray({DIB.getOrCreateSubrange(0, 1)}));
    // FIXME > how to remove lower bound from subrange?

    auto *DebugMapMaxEntriesArray = DIB.createArrayType(
        /*Size=*/8192 * 32,
        /*AlignInBits=*/0,
        /*Ty=*/Int,
        /*Subscripts=*/DIB.getOrCreateArray({DIB.getOrCreateSubrange(0, 8192)}));
    // FIXME > how to remove lower bound from subrange?

    // FIXME > make this distinct (DICompositeType::getDistinct?)
    auto *DebugStructType = DIB.createStructType(
        /*Scope=*/DebugCU,
        /*Name=*/StructName,
        /*File=*/DebugFile,
        /*LineNumber=*/0,
        /*SizeInBits8=*/256,
        /*AlignInBits=*/0,
        /*Flags=*/DINode::FlagZero,
        /*DerivedFrom=*/nullptr,
        /*Elements=*/nullptr);

    auto *DebugMapTypeField = DIB.createMemberType(
        /*Scope=*/DebugStructType,
        /*Name=*/"type",
        /*File=*/DebugFile,
        /*LineNo=*/0,
        /*SizeInBits=*/64,
        /*AlignInBits=*/0,
        /*OffsetInBits=*/0 * 64,
        /*Flags=*/DINode::FlagZero,
        /*Ty=*/DIB.createPointerType(DebugMapTypeArray, 64));

    auto *DebugMapMaxEntriesField = DIB.createMemberType(
        /*Scope=*/DebugStructType,
        /*Name=*/"max_entries",
        /*File=*/DebugFile,
        /*LineNo=*/0,
        /*SizeInBits=*/64,
        /*AlignInBits=*/0,
        /*OffsetInBits=*/1 * 64,
        /*Flags=*/DINode::FlagZero,
        /*Ty=*/DIB.createPointerType(DebugMapMaxEntriesArray, 64));

    auto *DebugMapKeyField = DIB.createMemberType(
        /*Scope=*/DebugStructType,
        /*Name=*/"key",
        /*File=*/DebugFile,
        /*LineNo=*/0,
        /*SizeInBits=*/64,
        /*AlignInBits=*/0,
        /*OffsetInBits=*/2 * 64,
        /*Flags=*/DINode::FlagZero,
        /*Ty=*/DIB.createPointerType(LLUInt, 64));

    auto *DebugMapValueField = DIB.createMemberType(
        /*Scope=*/DebugStructType,
        /*Name=*/"value",
        /*File=*/DebugFile,
        /*LineNo=*/0,
        /*SizeInBits=*/64,
        /*AlignInBits=*/0,
        /*OffsetInBits=*/3 * 64,
        /*Flags=*/DINode::FlagZero,
        /*Ty=*/DIB.createPointerType(LLUInt, 64));

    DebugStructType->replaceElements(
        DIB.getOrCreateArray({DebugMapTypeField, DebugMapMaxEntriesField,
                              DebugMapKeyField, DebugMapValueField}));

    auto *DebugMapGlobal = DIB.createGlobalVariableExpression(
        /*Context=*/DebugCU,
        /*Name=*/MapName,
        /*LinkageName=*/"",
        /*File=*/DebugFile,
        /*LineNo=*/0,
        /*Ty=*/DebugStructType,
        /*IsLocalToUnit=*/MapGlobal->hasLocalLinkage(),
        /*IsDefinition=*/true,
        /*Expr=*/nullptr,
        /*Decl=*/nullptr,
        /*TemplateParams=*/nullptr,
        /*AlignInBits=*/0);

    MapGlobal->addDebugInfo(DebugMapGlobal);

    errs() << DebugCU->getRawGlobalVariables() << "\n";

    errs() << DebugCU->getGlobalVariables().size() << "\n";

    // auto *x = MDTuple::get(CTX, DebugMapGlobal);

    // auto *DIGVs = dyn_cast_or_null<MDTuple>(DebugCU->getRawGlobalVariables());

    // MDTuple::get(CTX, DebugCU->getGlobalVariables().get());
    SmallVector<Metadata *> GlobalsVector;
    for (auto *DIGlobalVar : DebugCU->getGlobalVariables())
    {
        GlobalsVector.push_back(DIGlobalVar);
    }
    GlobalsVector.push_back(DebugMapGlobal);

    // auto Globals = DebugCU->getGlobalVariables().get();
    // Globals

    // DebugCU->replaceGlobalVariables(MDTuple::get(CTX, DebugMapGlobal));
    DebugCU->replaceGlobalVariables(MDTuple::get(CTX, GlobalsVector));

    // //MDTupleTypedArrayWrapper

    // llvm::ValueAsMetadata::getConstant(MapGlobal);

    appendToUsed(M, MapGlobal); // FIXME ? appendToCompilerUsed

    DIB.finalize();

    return MapVar;
}

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
            // TODO(leodido) > almost certainly the following if doesn't make sense for "llvm.used" array
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

    bool stripSectionsWithPrefix(Module &M, StringRef Prefix)
    {
        bool Changed = false;
        for (auto gv_iter = M.global_begin(); gv_iter != M.global_end(); gv_iter++)
        {
            GlobalVariable *GV = &*gv_iter;
            if (GV->hasSection() && GV->getSection().startswith(Prefix))
            {
                errs() << "stripping " << GV->getName() << " section\n";
                GV->setSection("");
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

        for (auto gv_iter = M.global_begin(); gv_iter != M.global_end(); gv_iter++)
        {
            GlobalVariable *GV = &*gv_iter;
            if (GV->hasName())
            {
                auto Name = GV->getName();
                if (Name.startswith("__profd") && GV->getValueType()->isStructTy())
                {
                    errs() << "converting " << Name << " struct to globals\n";

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
                        /*isConstant=*/false,
                        /*Linkage=*/GlobalVariable::ExternalLinkage,
                        /*Initializer=*/ConstantInt::get(Ty, C0->getSExtValue()),
                        /*Name=*/Name + ".0",
                        /*InsertBefore=*/GV);
                    GV0->setDSOLocal(true);
                    GV0->setAlignment(MaybeAlign(8));

                    appendToUsed(M, GV0);

                    ToDelete.push_back(GV);

                    Changed = true;
                }
                else if (Name.startswith("__covrec") && GV->getValueType()->isStructTy())
                {
                    // errs() << "converting " << Name << " struct to globals\n";
                    // TODO(leodido)
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

                    appendToUsed(M, GV1);

                    ToDelete.push_back(GV);
                }
            }
        }

        for (auto *GV : ToDelete)
        {
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
                else if (GV->getName().startswith("__profd") && GV->getName().endswith(".0"))
                {
                    auto *DebugGVE = DIB.createGlobalVariableExpression(
                        /*Context=*/DebugCU,
                        /*Name=*/GV->getName(),
                        /*LinkageName=*/"",
                        /*File=*/DebugFile,
                        /*LineNo=*/0,
                        /*Ty=*/DIB.createBasicType("long long int", 64, dwarf::DW_ATE_signed),
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

    // This sequence of calls is not random at all
    instrumented |= deleteGVarByName(M, "llvm.global_ctors");
    instrumented |= deleteFuncByName(M, "__llvm_profile_init");
    instrumented |= deleteFuncByName(M, "__llvm_profile_register_function");
    instrumented |= deleteFuncByName(M, "__llvm_profile_register_names_function");
    instrumented |= fixupUsedGlobals(M);
    instrumented |= deleteFuncByName(M, "__llvm_profile_runtime_user");
    instrumented |= deleteGVarByName(M, "__llvm_profile_runtime");
    instrumented |= stripSectionsWithPrefix(M, "__llvm_prf");
    instrumented |= convertStructs(M);
    instrumented |= annotateCounters(M);

    // for (auto &F : M)
    // {
    //     instrumented |= runOnFunction(F, M);
    // }

    return instrumented;
}

bool BPFCov::runOnFunction(Function &F, Module &M)
{
    if (F.isDeclaration())
    {
        return false;
    }
    // LLVM_DEBUG(dbgs() << "...\n");
    errs() << "instrumenting function: " << F.getName() << "\n";

    // auto insn_cnt = F.getInstructionCount();

    // todo >
    // CreateMap(M, F.getName());

    return true;
}

// bool BPFCov::runOnBasicBlock(BasicBlock &BB, Module &M) {
//   errs() << "BPFCov: runOnBasicBlock\n";
//   return false;
// }

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
                            MPM.addPass(BPFCov());
                            return true;
                        }
                        return false;
                    });
                // #2 Register for running automatically at "default<O2>"
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
        PM.add(new LegacyBPFCov());
    });