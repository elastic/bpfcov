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

#define DEBUG_TYPE "bpf-cov"

// NOTE > LLVM_DEBUG requires a LLVM built with NDEBUG unset
// NOTE > Then use with opt -debug

using namespace llvm;

std::string Prefix = "bpfcov_";
std::string Suffix = "_map";

// M.getIdentifiedStructTypes()
// IRBuilder<> IRB(C);
// auto &DL = M.getDataLayout();
// IRB.getInt32Ty();

//-----------------------------------------------------------------------------
// Utility functions
//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------
// Implementation
//-----------------------------------------------------------------------------

PreservedAnalyses BPFCov::run(Module &M, ModuleAnalysisManager &)
{
    bool changed = runOnModule(M);
    return (changed ? PreservedAnalyses::none() : PreservedAnalyses::all());
}

bool BPFCov::runOnModule(Module &M)
{
    errs() << "runOnModule\n"; // LLVM_DEBUG(dbgs() << "runOnModule\n");

    bool instrumented = false;

    for (auto &F : M)
    {
        instrumented |= runOnFunction(F, M);
    }

    return instrumented;
}

bool BPFCov::runOnFunction(Function &F, Module &M)
{
    if (F.isDeclaration())
    {
        return false;
    }
    // LLVM_DEBUG(dbgs() << "runOnFunction\n");
    errs() << "runOnFunction: " << F.getName() << "\n";

    // auto insn_cnt = F.getInstructionCount();

    // todo >
    CreateMap(M, F.getName());

    return true;
}

// bool BPFCov::runOnBasicBlock(BasicBlock &BB, Module &M) {
//   errs() << "BPFCov: runOnBasicBlock\n";
//   return false;
// }

//-----------------------------------------------------------------------------
// New PM / Registration
//-----------------------------------------------------------------------------
PassPluginLibraryInfo getBPFCovPluginInfo()
{
    return {LLVM_PLUGIN_API_VERSION, "simple-pass", LLVM_VERSION_STRING,
            [](PassBuilder &PB)
            {
                // #1 Regiser "opt -passes=simple-pass"
                // PB.registerPipelineParsingCallback(
                //     [&](StringRef Name, ModulePassManager &MPM,
                //         ArrayRef<PassBuilder::PipelineElement>) {
                //       if (Name == "simple-pass") {
                //         MPM.addPass(BPFCov());
                //         return true;
                //       }
                //       return false;
                //     });
                // #2 Register for running automatically at "-O2"
                PB.registerPipelineStartEPCallback(
                    [&](ModulePassManager &MPM,
                        ArrayRef<PassBuilder::OptimizationLevel> OLevels)
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

//-----------------------------------------------------------------------------
// Legacy PM / Implementation
//-----------------------------------------------------------------------------

char LegacyBPFCov::ID = 0;

bool LegacyBPFCov::runOnModule(llvm::Module &M)
{
    errs() << "runOnModule (Legacy Pass Manager)\n";
    return Impl.runOnModule(M);
}

void LegacyBPFCov::print(raw_ostream &OutStream, const Module *) const
{
    OutStream << "BPFCov (Legacy Pass Manager)\n";
}

//-----------------------------------------------------------------------------
// Legacy PM / Registration
//-----------------------------------------------------------------------------

static RegisterPass<LegacyBPFCov> X(/*PassArg=*/DEBUG_TYPE,
                                    /*Name=*/"BPFCov (Legacy Pass Manager)",
                                    /*CFGOnly=*/false,
                                    /*is_analysis=*/false);

static RegisterStandardPasses RegisterBPFCov(
    PassManagerBuilder::EP_EarlyAsPossible,
    [](const PassManagerBuilder &, legacy::PassManagerBase &PM)
    {
        PM.add(new LegacyBPFCov());
    });