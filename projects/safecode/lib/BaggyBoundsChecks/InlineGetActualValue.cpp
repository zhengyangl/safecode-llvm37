//===- InlineGetActualValue.cpp - Inline pchk_getActualValue function ----- --//
//
//                          The SAFECode Compiler
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This pass replaces calls to pchk_getActualValue functions within inline code
// to perform the check.  It is designed to provide the advantage of libLTO without
// libLTO.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "inline_get_actual_value_functions"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "safecode/InlineGetActualValue.h"
#include "safecode/Utility.h"
#include "safecode/Runtime/BBMetaData.h"
#include "llvm/Transforms/Utils/Cloning.h"

namespace {
STATISTIC (InlinedGetActualValue, "Number of pchk_getActualValue Functions Inlined");
}

namespace llvm {
char InlineGetActualValue::ID = 0;
}

using namespace llvm;

//
// Method: castToInt()
//
// Description:
//  Cast the given pointer value into an integer.
//
static Value *
castToInt (Value * Pointer, BasicBlock * BB) {
  //
  // Assert that the caller is giving us a pointer value.
  //
  assert (isa<PointerType>(Pointer->getType()));

  //
  // Get information on the size of pointers.
  //
  const DataLayout & TD = BB->getModule()->getDataLayout();

  //
  // Create the actual cast instrution.
  //
  return new PtrToIntInst (Pointer, TD.getIntPtrType(Pointer->getType()), "tmpi", BB);
}

//
// Method: inlineCheck ()
//
// Description:
//  Find the checks that need to be inlined and inline them.
//
// Inputs:
//  F - A pointer to the function.  Calls to this function will be inlined.
//      The pointer is allowed to be NULL.
//
// Return value:
//  true  - One or more calls to the check were inlined.
//  false - No calls to the check were inlined.
//
bool
llvm::InlineGetActualValue::inlineCheck (Function * F) {
  //
  // Get the runtime function in the code.  If no calls to the run-time
  // function were added to the code, do nothing.
  //
  if (!F) return false;

  // Get prerequisites for InlineFunctionInfo
  CallGraph &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();
  AssumptionCacheTracker *ACT = &getAnalysis<AssumptionCacheTracker>();
  AliasAnalysis *AA = &getAnalysis<AliasAnalysis>();

  //
  // Iterate though all calls to the function and search for pointers that are
  // checked but only used in comparisons.  If so, then schedule the check
  // (i.e., the call) for removal.
  //
  bool modified = false;
  std::vector<CallInst *> CallsToInline;
  for (Value::user_iterator FU = F->user_begin(); FU != F->user_end(); ++FU) {
    //
    // We are only concerned about call instructions; any other use is of
    // no interest to the organization.
    //
    if (CallInst * CI = dyn_cast<CallInst>(*FU)) {
        CallsToInline.push_back (CI);
    }
  }

  //
  // Update the statistics and determine if we will modify anything.
  //
  if (CallsToInline.size()) {
    modified = true;
  }

  //
  // Inline all of the fast calls we found.
  //
  InlineFunctionInfo IFI(&CG, AA, ACT);
  for (unsigned index = 0; index < CallsToInline.size(); ++index) {
    InlineFunction (CallsToInline[index], IFI);
    ++ InlinedGetActualValue;
  }

  return modified;
}


bool
llvm::InlineGetActualValue::createGetActualValueBodyFor (Function * F) {
  //
  // If the function does not exist, do nothing.
  //
  if (!F) return false;
  //
  // If the function has a body, do nothing.
  //
  if (!(F->isDeclaration())) return false;

  LLVMContext &Context = F->getContext();

  BasicBlock *EntryBB = BasicBlock::Create (Context, "entry", F);

  Function::arg_iterator arg = F->arg_begin();
  Value *Pool = arg, *PoolInt = castToInt (arg++, EntryBB);
  Value *Ptr = arg, *PtrInt = castToInt (arg++, EntryBB);

  BasicBlock *GoodBB = BasicBlock::Create (Context, "good", F);
  ReturnInst::Create (F->getContext(), Ptr, GoodBB);

  BasicBlock *NotPassRewrittenCheckBB = BasicBlock::Create (Context,
                                                            "not_pass_rewritten_check", F);

  uintptr_t InvalidUpper = 0xf0000000;
  uintptr_t InvalidLower = 0xc0000000;
  Constant * InvalidLowerC = ConstantInt::get (PtrInt->getType(),
                                               InvalidLower,
                                               false);
  Constant * InvalidUpperC = ConstantInt::get (PtrInt->getType(),
                                               InvalidUpper,
                                               false);

  ICmpInst * Compare1 = new ICmpInst (*EntryBB,
                                      CmpInst::ICMP_UGT,
                                      PtrInt,
                                      InvalidLowerC,
                                      "cmp1");
  ICmpInst * Compare2 = new ICmpInst (*EntryBB,
                                      CmpInst::ICMP_ULT,
                                      PtrInt,
                                      InvalidUpperC,
                                      "cmp2");

  Value * Compare = BinaryOperator::Create (Instruction::And,
                                            Compare1,
                                            Compare2,
                                            "and",
                                            EntryBB);

  Constant *FGetActualValue =
      F->getParent()->getOrInsertFunction("__sc_bb_getActualValue",
                                          getVoidPtrType(Context),
                                          Pool->getType(),
                                          Ptr->getType(),
                                          NULL);

  Value* TmpArgArray[2];
  TmpArgArray[0] = Pool;
  TmpArgArray[1] = Ptr;
  CallInst *CallGetActualValue
      = CallInst::Create(FGetActualValue,
                         ArrayRef<Value*>(TmpArgArray, 2),
                         "call_getActualValue",
                         NotPassRewrittenCheckBB);

  ReturnInst::Create (Context, CallGetActualValue, NotPassRewrittenCheckBB);

  BranchInst::Create (NotPassRewrittenCheckBB, GoodBB, Compare, EntryBB);
  F->setLinkage (GlobalValue::InternalLinkage);
  return true;
}

bool
llvm::InlineGetActualValue::runOnModule (Module &M) {
  createGetActualValueBodyFor (M.getFunction("pchk_getActualValue"));

  inlineCheck (M.getFunction ("pchk_getActualValue"));
  return true;
}

