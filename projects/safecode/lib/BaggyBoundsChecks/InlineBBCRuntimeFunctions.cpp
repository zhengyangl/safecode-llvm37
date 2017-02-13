//===- InlineBBCRuntimeFunctions.cpp - Inline BBC RuntimeFunctions--------- --//
//
//                          The SAFECode Compiler
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This pass replaces calls to bbc runtime functions within inline code to
// perform the check.  It is designed to provide the advantage of libLTO without
// libLTO.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "inline_bbc_runtime_functions"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "safecode/InlineBBCRuntimeFunctions.h"
#include "safecode/Utility.h"
#include "safecode/Runtime/BBMetaData.h"
#include "llvm/Transforms/Utils/Cloning.h"

namespace {
STATISTIC (InlinedBBCChecks, "Number of BBC Runtime Functions Inlined");
}

namespace llvm {
template <bool T> char InlineBBCRuntimeFunctions<T>::ID = 0;
template class InlineBBCRuntimeFunctions<true>;
template class InlineBBCRuntimeFunctions<false>;
}

using namespace llvm;

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
template <bool T>
bool
llvm::InlineBBCRuntimeFunctions<T>::inlineCheck (Function * F) {
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
    //    Inlined += CallsToInline.size();
  }

  //
  // Inline all of the fast calls we found.
  //
  InlineFunctionInfo IFI(&CG, AA, ACT);
  for (unsigned index = 0; index < CallsToInline.size(); ++index) {
    InlineFunction (CallsToInline[index], IFI);
    ++ InlinedBBCChecks;
  }

  return modified;
}

//
// Function: createEmitLSReportBlock()
//
// Description:
//  Create a basic block which will cause the program to terminate and emit the report.
//
// Inputs:
//  F - A reference to a function to which a faulting basic block will be added.
//  Node - The pointer generating the violation
//  SourceFilep - The source file path, as c style string
//  LineNo - The line number of the violation
//
static BasicBlock *
createEmitLSReportBlock (Function & F, Value *Node, Value *SourceFilep, Value *LineNo) {
  Type *VoidTy = Type::getVoidTy(F.getContext());
  Constant * EmitReport = F.getParent()->getOrInsertFunction("__sc_bb_emit_report",
                                                             VoidTy,
                                                             Node->getType(),
                                                             SourceFilep->getType(),
                                                             LineNo->getType(),
                                                             NULL);

  //
  // Create the basic block.
  //
  BasicBlock * FaultBB = BasicBlock::Create (F.getContext(), "report-debug", &F);

  Value* TmpArgArray[3];
  TmpArgArray[0] = Node;
  TmpArgArray[1] = SourceFilep;
  TmpArgArray[2] = LineNo;
  CallInst::Create(EmitReport,
                   ArrayRef<Value*>(TmpArgArray, 3),
                   "",
                   FaultBB);

  //
  // Terminate the basic block with an unreachable instruction.
  //
  new UnreachableInst (F.getContext(), FaultBB);

  return FaultBB;
}

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
// Method: castToInt()
//
// Description:
//  Cast the given pointer value into an integer.
//
static Value *
castToPtr (Value * Integer, BasicBlock * BB) {
  //
  // Assert that the caller is giving us a pointer value.
  //
  assert (isa<IntegerType>(Integer->getType()));

  //
  // Create the actual cast instrution.
  //
  return new IntToPtrInst (Integer, getVoidPtrType(*(BB->getModule())), "tmpp", BB);
}

//
// Function: insertIsRewrittenPtr()
//
// Description:
//  Create instructions to check whether the input pointer V is a rewritten pointer or
//  not. Then insert a branch instruction, if V is not a rewritten ptr, jump to
//  PassRewrittenCheckBB, otherwise jump to FaultBB. All the instructions are inserted
//  to BB.
//
// Inputs:
//  V - The pointer to be checked
//  BB - The basic block to be inserted
//  PassRewrittenCheckBB - The basic block to be jumped when V is not a rewritten pointer
//  FaultBB - The basic block to be jumped when V is a rewritten pointer
//
static void
insertIsRewrittenPtr (Value *V,
                      BasicBlock *BB,
                      BasicBlock *PassRewrittenCheckBB,
                      BasicBlock *FaultBB) {

  //
  // Assert that the caller is giving us a casted integer value.
  //
  assert (isa<IntegerType>(V->getType()));

  //
  // if ((InvalidLower < ptr ) && (ptr < InvalidUpper))
  //
  GlobalVariable *GVL = BB->getModule()->getGlobalVariable("_ZN8safecode12InvalidLowerE");
  GlobalVariable *GVU = BB->getModule()->getGlobalVariable("_ZN8safecode12InvalidUpperE");
  LoadInst *InvalidLowerC = new LoadInst(GVL, "il", BB);
  LoadInst *InvalidUpperC = new LoadInst(GVU, "iu", BB);

  ICmpInst * Compare1 = new ICmpInst (*BB,
                                      CmpInst::ICMP_UGT,
                                      V,
                                      InvalidLowerC,
                                      "cmp1");
  ICmpInst * Compare2 = new ICmpInst (*BB,
                                      CmpInst::ICMP_ULT,
                                      V,
                                      InvalidUpperC,
                                      "cmp2");

  Value * Compare = BinaryOperator::Create (Instruction::And,
                                            Compare1,
                                            Compare2,
                                            "and",
                                            BB);

  BranchInst::Create (FaultBB, PassRewrittenCheckBB, Compare, BB);
}

//
// Function: insertZeroCheck()
//
// Description:
//  Create instructions to check whether the integer V is zero. Then insert a branch
//  instruction, if V is zero, jump to GoodBB, otherwise jump to NotPassZeroCheckBB.
//  All the instructions are inserted to BB.
//
// Inputs:
//  V - The integer to be checked
//  BB - The basic block to be inserted
//  GoodBB - If V is zero, jump to GoodBB
//  NotPassZeroCheckBB - If V is not zero, jump to NotPassZeroCheckBB
//
static void
insertZeroCheck (Value *V,
                 BasicBlock *BB,
                 BasicBlock *GoodBB,
                 BasicBlock *NotPassZeroCheckBB) {

  //
  // Assert that the caller is giving us a casted integer value.
  //
  assert (isa<IntegerType>(V->getType()));
  ICmpInst * Compare = new ICmpInst (*BB,
                                     CmpInst::ICMP_EQ,
                                     V,
                                     ConstantInt::get (V->getType(), 0, false),
                                     "cmp");

  BranchInst::Create (GoodBB, NotPassZeroCheckBB, Compare, BB);
}

//
// Function: insertIsSrcDstEqualCheck()
//
// Description:
//  This function create instructions to implement the following if statement.
//
//      if (!isRewritePtr((void *)Source) && (Source == Dest)) return Dest;
//
//  Firstly insert a rewrite check on Src by calling insertIsRewrittenPtr. if Src is
//  a rewritten pointer, then directly jump it to NotPassIsSrcDstEqualCheckBB. If src
//  is not a rewritten pointer, then we insert icmp instruction to check whether
//  Src == Dst. If Src == Dst, then jump to GoodBB, else jump to NotPassIsSrcdstEqualCheckbb.
//
// Inputs:
//  Src - The pointer to be checked
//  Dst - The pointer to be checked
//  BB - The basic block to be inserted
//  GoodBB - If Src is not a rewritten pointer, and Src == Dst, then jump to this.
//  NotPassIsSrcDstEqualCheckBB - If Src is a rewritten pointer, or Src is not a rewritten
//                                pointer and is not equal to Dst, jump to this basic block.
//
static void
insertIsSrcDstEqualCheck (Value *Src,
                          Value *Dst,
                          BasicBlock *BB,
                          BasicBlock *GoodBB,
                          BasicBlock *NotPassIsSrcDstEqualCheckBB) {

  //
  // Assert that the caller is giving us a casted integer value.
  //
  assert (isa<IntegerType>(Src->getType()));
  assert (isa<IntegerType>(Dst->getType()));
  BasicBlock * SrcIsNotRewrittenBB = BasicBlock::Create (Src->getContext(),
                                                         "src_is_not_rewritten",
                                                         BB->getParent());

  insertIsRewrittenPtr (Src, BB, SrcIsNotRewrittenBB, NotPassIsSrcDstEqualCheckBB);

  ICmpInst * Compare = new ICmpInst (*SrcIsNotRewrittenBB,
                                     CmpInst::ICMP_EQ,
                                     Src,
                                     Dst,
                                     "cmp_is_src_dst_equal");

  BranchInst::Create (GoodBB, NotPassIsSrcDstEqualCheckBB, Compare, SrcIsNotRewrittenBB);
}

//
// Function: insertGetBBCLength()
//
// Description:
//  This function insert instructions which looks up the baggy bounds size table, and extract
//  the exact slot size of the Ptr. Besides, this function also insert instructions to
//  check whether the slot size is legal (e != 0 and e <= 12). If the slot size is not
//  legal, jump to GoodBB (ignores slot size info from baggy bounds size table). If
//  the slot size is legal, jump to NotPassBBLengthCheckBB. All instructions are inserted
//  to BB.
//
// Inputs:
//  Ptr - The pointer to be checked
//  BB - The basic block to be inserted
//  GoodBB - If slot size is illegal, jump to this basic block.
//  NotPassBBLengthCheckBB - If slot size is legal, jump to this basic block.
//
// Outputs:
//  LCasted - Casted (i64) slot size of Ptr.
//
static Value *
insertGetBBCLength (Value *Ptr,
                     BasicBlock *BB,
                     BasicBlock *GoodBB,
                     BasicBlock *NotPassBBLengthCheckBB) {

  //
  // Assert that the caller is giving us a casted integer value.
  //
  assert (isa<IntegerType>(Ptr->getType()));

  Module * M = BB->getModule();

  // Get the address of baggy bounds size table
  GlobalVariable *GV = M->getGlobalVariable("__baggybounds_size_table_begin");
  LoadInst *TBL = new LoadInst(GV, "tbl", BB);

  // Logic right shift the Ptr by 4.
  BinaryOperator *BO = BinaryOperator::Create (Instruction::LShr,
                                               Ptr,
                                               ConstantInt::get (Ptr->getType(), 4, false),
                                               "shifted",
                                               BB);

  // Get the pointer to the actual slot size.
  ArrayRef<Value *> ArefBO (BO);
  GetElementPtrInst *GEPI = GetElementPtrInst::Create (Type::getInt8Ty(M->getContext()),
                                                       TBL,
                                                       ArefBO,
                                                       "index",
                                                       BB);

  // Load the actual slot size, the type of result should be i8.
  LoadInst *LLength = new LoadInst(GEPI, "length", BB);

  //
  // Perform the legal check on the slot size. If e == 0 or e > 12, then mark this slot
  // size as illegal
  //
  ICmpInst * CompareEqZero = new ICmpInst (*BB,
                                     CmpInst::ICMP_EQ,
                                     LLength,
                                     ConstantInt::get (LLength->getType(), 0, false),
                                     "cmp_eq_zero");

  ICmpInst * CompareGtTwelve = new ICmpInst (*BB,
                                             CmpInst::ICMP_UGT,
                                             LLength,
                                             ConstantInt::get (LLength->getType(), 12, false),
                                             "cmp_gt_twelve");

  BinaryOperator *BLenCheck = BinaryOperator::Create (Instruction::Or,
                                                      CompareEqZero,
                                                      CompareGtTwelve,
                                                      "cmp_len_check",
                                                      BB);

  // Cast the slot size to i64 for furthur calculation.
  Value *LCasted = castTo(LLength, Type::getInt64Ty(M->getContext()),
                          LLength->getName() + ".casted",
                          NotPassBBLengthCheckBB);
  BranchInst::Create (GoodBB, NotPassBBLengthCheckBB, BLenCheck, BB);
  return LCasted;
}

//
// Function: insertGetBBCRange()
//
// Description:
//  This functions inserts instructions to calculate the lower and upper bounds of the input
//  Ptr and Length. All the instructions are inserted to BB.
//
// Inputs:
//  Ptr - The base pointer used in the bounds calculation
//  Length - The slot size of Ptr used in the bounds calculation
//  BB - The basic block to be inserted
//
// Outputs:
//  ObjStart - The lower bound
//  ObjEnd - The Upper bound
//
std::tuple<Value *, Value*>
insertGetBBCRange (Value *Ptr, Value *Length ,BasicBlock *BB) {
  //
  // Assert that the caller is giving us a casted integer value.
  //
  assert (isa<IntegerType>(Ptr->getType()));
  assert (isa<IntegerType>(Length->getType()));

  //
  // Calculate lower bound:
  //   uintptr_t ObjStart = (uintptr_t)Node & ~((1<<e)-1);
  //
  Module *M = BB->getModule();
  BinaryOperator *BShrOne =
      BinaryOperator::Create (Instruction::Shl,
                              ConstantInt::get (Length->getType(),1, false),
                              Length,
                              "shl_one",
                              BB);
  BinaryOperator *BSubOne =
      BinaryOperator::Create (Instruction::Sub,
                              BShrOne,
                              ConstantInt::get (BShrOne->getType(),1, false),
                              "sub_one",
                              BB);
  BinaryOperator *BInv =
      BinaryOperator::Create (Instruction::Xor,
                              BSubOne,
                              ConstantInt::get (BSubOne->getType(), -1, false),
                              "inv",
                              BB);
  BinaryOperator *BObjStart =
      BinaryOperator::Create (Instruction::And,
                              Ptr,
                              BInv,
                              "obj_start",
                              BB);

  //
  // Calculate the address of BBMetaData.
  //  SlotEnd = ObjStart + (1 << e);
  //  MetaData = SlotEnd - sizeof(BBMetaData);
  //
  BinaryOperator *BSlotEnd =
      BinaryOperator::Create (Instruction::Add,
                              BShrOne,
                              BObjStart,
                              "slot_end",
                              BB);

  //
  // Get the upper bound
  //  uintptr_t ObjEnd = SlotEnd - 1;
  //
  BinaryOperator *BObjSizeSubOne =
      BinaryOperator::Create (Instruction::Sub,
                              BSlotEnd,
                              ConstantInt::get (BSlotEnd->getType(),
                                                1, false),
                              "obj_size_sub_one",
                              BB);

  BinaryOperator *BObjEnd =
      BinaryOperator::Create (Instruction::Add,
                              BObjSizeSubOne,
                              BObjStart,
                              "obj_end",
                              BB);

  return std::make_tuple<Value*, Value*> (BObjStart, BObjEnd);
}

//
// Function: insertBBPoolCheck()
//
// Description:
//  This function inserts instructions for poolcheckui function. All the
//  instructions are inserted to basic block BB.
//
// Inputs:
//  Ptr - The pointer to be checked
//  Length - The slot size of Ptr used in the bounds calculation
//  BB - The basic block to be inserted
//  GoodBB - jump to this basic block if the program passes the poolcheckui check
//  FaultBB - jump to this basic block if the program does not pass the poolcheckui check
//
static void
insertBBPoolCheck (Value *Ptr,
               Value *Len,
               BasicBlock *BB,
               BasicBlock *GoodBB,
               BasicBlock *FaultBB) {
  //
  // Assert that the caller is giving us a casted integer value.
  //
  assert (isa<IntegerType>(Ptr->getType()));
  assert (isa<IntegerType>(Len->getType()));

  Module *M = BB->getModule();

  BasicBlock * NotPassBBLengthCheckBB =
      BasicBlock::Create (M->getContext(),
                          "not_pass_bblength_check",
                          BB->getParent());

  //
  // Get Memory Object Bounds from Baggy Bounds Size Table.
  //
  Value * BBLength =
      insertGetBBCLength (Ptr, BB, GoodBB, NotPassBBLengthCheckBB);
  std::tuple<Value*, Value*> BBRange =
      insertGetBBCRange(Ptr, BBLength, NotPassBBLengthCheckBB);
  Value *ObjStart = std::get<0>(BBRange);
  Value *ObjEnd = std::get<1>(BBRange);

  //
  // Get the end of the memory object, aka NodeEnd.
  // uintptr_t NodeEnd = (uintptr_t)Node + length -1;
  //
  BinaryOperator *BLenSubOne =
      BinaryOperator::Create (Instruction::Sub,
                              Len,
                              ConstantInt::get (Len->getType(), 1, false),
                              "len_sub_one",
                              NotPassBBLengthCheckBB);

  BinaryOperator *BNodeEnd =
      BinaryOperator::Create (Instruction::Add,
                              Ptr,
                              BLenSubOne,
                              "node_end",
                              NotPassBBLengthCheckBB);

  //
  // Compare the NodeEnd with the bounds of the memory object.
  //
  //    !((ObjStart <= NodeEnd) &&  (NodeEnd <= ObjEnd))
  // ->  !(ObjStart <= NodeEnd) || !(NodeEnd <= ObjEnd)
  // ->   (ObjStart >  NodeEnd) ||  (NodeEnd >  ObjEnd)
  //
  ICmpInst * ICmpCompareLHS =
      new ICmpInst (*NotPassBBLengthCheckBB,
                    CmpInst::ICMP_UGT,
                    ObjStart,
                    BNodeEnd,
                    "cmp_lhs");
  ICmpInst * ICmpCompareRHS =
      new ICmpInst (*NotPassBBLengthCheckBB,
                    CmpInst::ICMP_UGT,
                    BNodeEnd,
                    ObjEnd,
                    "cmp_rhs");
  BinaryOperator *BOEmitReport =
      BinaryOperator::Create (Instruction::Or,
                              ICmpCompareLHS,
                              ICmpCompareRHS,
                              "call_emit_report",
                              NotPassBBLengthCheckBB);

  BranchInst::Create (FaultBB,
                      GoodBB,
                      BOEmitReport,
                      NotPassBBLengthCheckBB);
  return;
}

//
// Function: insertIsPointerInBounds()
//
// Description:
//  This function inserts instructions for _barebone_pointer_in_bounds function.
//  All the instructions are inserted to basic block BB.
//
// Inputs:
//  Src - The base pointer
//  Dst - The pointer to be accessed.
//  BB - The basic block to be inserted
//  GoodBB - jump to this basic block if the program passes the check
//  NotPassIsPointerInBoundsBB - jump to this basic block if the program does
//                               not pass the check
//
static void
insertIsPointerInBounds (Value *Source, Value *Dest,
                         BasicBlock *BB,
                         BasicBlock *GoodBB,
                         BasicBlock *NotPassIsPointerInBoundsBB) {
  //
  // Assert that the caller is giving us a casted integer value.
  //
  assert (isa<IntegerType>(Source->getType()));
  assert (isa<IntegerType>(Dest->getType()));

  Module *M = BB->getModule();
  BasicBlock * NotPassBBLengthCheckBB =
      BasicBlock::Create (M->getContext(),
                          "not_pass_bbc_length_check",
                          BB->getParent());
  // Get the Object BB Length from Baggy Bounds size table.
  Value * BBLength =
      insertGetBBCLength (Source, BB, GoodBB, NotPassBBLengthCheckBB);

  // Get the bounds with the input address Source and BB Length.
  std::tuple<Value*, Value*> BBRange =
      insertGetBBCRange(Source, BBLength, NotPassBBLengthCheckBB);
  Value *ObjStart = std::get<0>(BBRange);
  Value *ObjEnd = std::get<1>(BBRange);

  //
  // Compare the Source and Dest with the bounds of that memory object.
  //
  // The original runtime code is as following.
  //   return !(begin <= Source && Source < end && begin <= Dest && Dest < end);
  //
  // Since our ObjEnd calculated by insertGetBBRange is equals to (end - 1), we
  // need turn the < to <= on Source < end and Dest < end.
  //
  // !( (ObjStart <= Source) && (Source <= ObjEnd) &&
  //    (ObjStart <= Dest ) && (Dest <= end))
  //
  ICmpInst * ICmpBeginLESource =
      new ICmpInst (*NotPassBBLengthCheckBB,
                    CmpInst::ICMP_ULE,
                    ObjStart,
                    Source,
                    "cmp_begin_le_source");
  ICmpInst * ICmpSourceLTEnd =
      new ICmpInst (*NotPassBBLengthCheckBB,
                    CmpInst::ICMP_ULE,
                    Source,
                    ObjEnd,
                    "cmp_source_lt_end");
  ICmpInst * ICmpBeginLEDest =
      new ICmpInst (*NotPassBBLengthCheckBB,
                    CmpInst::ICMP_ULE,
                    ObjStart,
                    Dest,
                    "cmp_begin_le_dest");
  ICmpInst * ICmpDestLTEnd =
      new ICmpInst (*NotPassBBLengthCheckBB,
                    CmpInst::ICMP_ULE,
                    Dest,
                    ObjEnd,
                    "cmp_dest_lt_end");

  // Combine the compares with AND operators.
  BinaryOperator *BOCompareLeftHalf =
      BinaryOperator::Create (Instruction::And,
                              ICmpBeginLESource,
                              ICmpSourceLTEnd,
                              "compare_left_half",
                              NotPassBBLengthCheckBB);

  BinaryOperator *BOCompareRightHalf =
      BinaryOperator::Create (Instruction::And,
                              ICmpBeginLEDest,
                              ICmpDestLTEnd,
                              "compare_right_half",
                              NotPassBBLengthCheckBB);

  BinaryOperator *BOCompare =
      BinaryOperator::Create (Instruction::And,
                              BOCompareLeftHalf,
                              BOCompareRightHalf,
                              "compare",
                              NotPassBBLengthCheckBB);

  //
  // If compare fails, aka neither Source nor Dest is in range, then we jump to
  // NotPassIsPointerInBoundsBB, otherwise, we jump to GoodBB and simply return
  // the Dest pointer.
  //
  BranchInst::Create (GoodBB,
                      NotPassIsPointerInBoundsBB,
                      BOCompare,
                      NotPassBBLengthCheckBB);
}

//
// Function: createGlobalDeclarations()
//
// Description:
//  This function insert the declaration of baggy bounds size table pointer as
//  a GlobalVariable
//
// Inputs:
//  M - The module to be inserted
//
template <bool isRewriteOOBDisabled>
bool
llvm::InlineBBCRuntimeFunctions<isRewriteOOBDisabled>
::createGlobalDeclarations (Module & M) {
  Type * VoidType  = Type::getVoidTy(M.getContext());
  Type * Int1Type  = IntegerType::getInt1Ty(M.getContext());
  Type * Int8Type  = IntegerType::getInt8Ty(M.getContext());
  Type * Int32Type = IntegerType::getInt32Ty(M.getContext());
  Type * VoidPtrType = PointerType::getUnqual(Int8Type);

  //
  // Add the memset function to the program.
  //
  M.getOrInsertFunction ("llvm.memset.p0i8.i32",
                         VoidType,
                         VoidPtrType,
                         Int8Type,
                         Int32Type,
                         Int32Type,
                         Int1Type,
                         NULL);

  const DataLayout & TD = M.getDataLayout();
  GlobalVariable *GV = M.getGlobalVariable("__baggybounds_size_table_begin");
  if (!GV) {
    GV = new GlobalVariable(M,
                            getVoidPtrType(M),
                            true,
                            GlobalVariable::ExternalLinkage,
                            nullptr,
                            "__baggybounds_size_table_begin");
  }
  if (isRewriteOOBDisabled) return true;
  GlobalVariable *GVL = M.getGlobalVariable("_ZN8safecode12InvalidLowerE");
  if (!GVL) {
    GVL = new GlobalVariable(M,
                             TD.getIntPtrType(getVoidPtrType(M)),
                             true,
                             GlobalVariable::ExternalLinkage,
                             nullptr,
                             "_ZN8safecode12InvalidLowerE");
  }

  GlobalVariable *GVU = M.getGlobalVariable("_ZN8safecode12InvalidUpperE");
  if (!GVU) {
    GVU = new GlobalVariable(M,
                             TD.getIntPtrType(getVoidPtrType(M)),
                             true,
                             GlobalVariable::ExternalLinkage,
                             nullptr,
                             "_ZN8safecode12InvalidUpperE");
  }
  return true;
}

//
// Function: createPoolCheckUIBodyFor
//
// Description:
//  This function create the implementation of poolcheckui_debug function
//
// Inputs:
//  F - The function to be implemented
//
template <bool isRewriteOOBDisabled>
bool
llvm::InlineBBCRuntimeFunctions<isRewriteOOBDisabled>::
createPoolCheckUIBodyFor (Function * F) {
  //
  // If the function does not exist, do nothing.
  //
  if (!F) return false;
  //
  // If the function has a body, do nothing.
  //
  if (!(F->isDeclaration())) return false;

  //
  // Create an entry block that will perform the comparisons and branch either
  // to the success block or the fault block.
  //
  LLVMContext &Context = F->getContext();
  BasicBlock *EntryBB = BasicBlock::Create (Context, "entry", F);
  //
  // Create a basic block that just returns.
  //
  BasicBlock *GoodBB = BasicBlock::Create (Context, "good", F);
  ReturnInst::Create (F->getContext(), GoodBB);

  BasicBlock *NotPassZeroLenCheckBB =
      BasicBlock::Create (Context,
                          "not_pass_zero_len_check", F);

  //
  // Add instructions to the entry block to compare the first dereferenced
  // address.
  //
  Function::arg_iterator arg = F->arg_begin();

  Value *Pool = castToInt (arg++, EntryBB);
  Value *Node = castToInt (arg++, EntryBB);
  Value *Length = castTo (arg++, Type::getInt64Ty(Context), "length", EntryBB);
  // Ignore TAG argument
  /* Value * TAG = */ arg ++;
  Value *SourceFilep = arg ++;
  Value *Lineno = arg;

  //
  // Create a basic block that handles the run-time check failures.
  //
  BasicBlock *FaultBB = createEmitLSReportBlock (*F, Node, SourceFilep, Lineno);

  insertZeroCheck (Length, EntryBB, GoodBB, NotPassZeroLenCheckBB);
  if (!isRewriteOOBDisabled) {
    BasicBlock *PassRewrittenCheckBB = BasicBlock::Create (Context,
                                                           "pass_rewritten_check", F);

    insertIsRewrittenPtr (Node, NotPassZeroLenCheckBB, PassRewrittenCheckBB, FaultBB);
    insertBBPoolCheck(Node, Length, PassRewrittenCheckBB, GoodBB, FaultBB);
  } else
    insertBBPoolCheck(Node, Length, NotPassZeroLenCheckBB, GoodBB, FaultBB);


  //
  // Make the function internal.
  //
  F->setLinkage (GlobalValue::InternalLinkage);
  return true;
}

//
// Function: createBoundsCheckUIBodyFor
//
// Description:
//  This function create the implementation of boundscheckui_debug function
//
// Inputs:
//  F - The function to be implemented
//
template <bool T>
bool
llvm::InlineBBCRuntimeFunctions<T>::createBoundsCheckUIBodyFor (Function * F) {
  //
  // If the function does not exist, do nothing.
  //
  if (!F) return false;
  //
  // If the function has a body, do nothing.
  //
  if (!(F->isDeclaration())) return false;

  LLVMContext &Context = F->getContext();
  Module *M = F->getParent();

  //
  // Create an entry block that will perform the comparisons and branch either
  // to the success block or the fault block.
  //
  BasicBlock *EntryBB =
      BasicBlock::Create (Context, "entry", F);

  //
  // Create a basic block that just returns.
  //
  BasicBlock *GoodBB =
      BasicBlock::Create (Context, "good", F);

  BasicBlock *NotPassIsSrcDstEqualCheckBB =
      BasicBlock::Create(Context,
                         "not_pass_is_src_dst_equal_check",
                         F);

  BasicBlock *NotPassIsPointerInBoundsBB =
      BasicBlock::Create(Context,
                         "not_pass_is_pointerinbounds_check",
                         F);

  Function::arg_iterator arg = F->arg_begin();

  Value *Pool = castToInt (arg++, EntryBB);
  Value *SourcePtr = arg, *Source = castToInt (arg++, EntryBB);
  Value *DestPtr = arg, *Dest = castToInt (arg++, EntryBB);

  ReturnInst::Create (F->getContext(), DestPtr, GoodBB);
  insertIsSrcDstEqualCheck (Source, Dest, EntryBB, GoodBB,
                            NotPassIsSrcDstEqualCheckBB);
  insertIsPointerInBounds (Source, Dest,
                           NotPassIsSrcDstEqualCheckBB,
                           GoodBB,
                           NotPassIsPointerInBoundsBB);

  //
  // The prototype of __sc_bb_getActualValueAndCheckAgain is as following.
  //  static inline void*
  //  __sc_bb_getActualValueAndCheckAgain (uintptr_t Source, uintptr_t Dest) ;
  //
  Constant *FCheckAgain =
      F->getParent()->getOrInsertFunction("__sc_bb_getActualValueAndCheckAgain",
                                          getVoidPtrType(*M),
                                          Type::getInt64Ty(Context),
                                          Type::getInt64Ty(Context),
                                          NULL);

  Value* TmpArgArray[2];
  TmpArgArray[0] = Source;
  TmpArgArray[1] = Dest;
  CallInst *CallCheckAgain
      = CallInst::Create(FCheckAgain,
                         ArrayRef<Value*>(TmpArgArray, 2),
                         "call_check_again",
                         NotPassIsPointerInBoundsBB);
  ReturnInst::Create (Context, CallCheckAgain, NotPassIsPointerInBoundsBB);
  F->setLinkage (GlobalValue::InternalLinkage);
  return true;
}

//
// Function: insertFindBinaryLogarithm ()
//
static
Value *
insertFindBinaryLogarithm (Value *Val, BasicBlock* ResultBB, BasicBlock *BB) {
  assert (isa<IntegerType>(Val->getType()));

  Module *M = BB->getModule();
  BasicBlock * BBCond = BasicBlock::Create (M->getContext(),
                                            "cond",
                                            BB->getParent());
  BasicBlock * BBLoop = BasicBlock::Create (M->getContext(),
                                            "loop",
                                            BB->getParent());

  AllocaInst * ACnt = new AllocaInst (Val->getType(), "cnt", BB);
  new StoreInst (ConstantInt::get (Val->getType(),
                                   0,
                                   false), ACnt, BB);
  BranchInst::Create(BBCond,BB);

  LoadInst * LCnt = new LoadInst(ACnt,"lcnt", BBCond);
  BinaryOperator *BShlOne;
  BShlOne = BinaryOperator::Create (Instruction::Shl,
                                    ConstantInt::get (Val->getType(),1, false),
                                    LCnt,
                                    "shr_one",
                                    BBCond);

  ICmpInst * ILT = new ICmpInst (*BBCond,
                                 CmpInst::ICMP_ULT,
                                 BShlOne,
                                 Val,
                                 "cond");

  BranchInst::Create(BBLoop, ResultBB, ILT ,BBCond);

  LoadInst * LCnt2 = new LoadInst(ACnt,"lcnt", BBLoop);

  BinaryOperator *BCnt2AddOne;
  BCnt2AddOne = BinaryOperator::Create (Instruction::Add,
                                       LCnt2,
                                       ConstantInt::get (Val->getType(),1, false),
                                       "lcnt_add_one",
                                       BBLoop);
  new StoreInst (BCnt2AddOne, ACnt, BBLoop);
  BranchInst::Create(BBCond, BBLoop);

  LoadInst * LResult = new LoadInst(ACnt, "result", ResultBB);

  return LResult;
}


//
// Function: insertInternalRegister ()
//
// Description:
//  This functions inserts instructions to calculate the lower and upper bounds of the input
//  Ptr and Length. All the instructions are inserted to BB.
//
// Inputs:
//  Ptr - The base pointer used in the bounds calculation
//  Length - The slot size of Ptr used in the bounds calculation
//  BB - The basic block to be inserted
//
// Outputs:
//  ObjStart - The lower bound
//  ObjEnd - The Upper bound
//
static
BasicBlock *
insertInternalRegister (Value *Ptr, Value *Length ,
                        BasicBlock *BB) {
  //
  // Assert that the caller is giving us a casted integer value.
  //
  assert (isa<IntegerType>(Ptr->getType()));
  assert (isa<IntegerType>(Length->getType()));

  Module *M = BB->getModule();
  BasicBlock * BBAfterFindLog =
      BasicBlock::Create (M->getContext(),
                          "after_find_log",
                          BB->getParent());

  Value *BBinaryLog = insertFindBinaryLogarithm (Length,
                                                  BBAfterFindLog,
                                                  BB);

  ICmpInst * ILessThanSlotSize =
      new ICmpInst (*BBAfterFindLog,
                    CmpInst::ICMP_ULT,
                    BBinaryLog,
                    ConstantInt::get (Length->getType(),
                                      4,
                                      false),
                    "less_than_slotsize");

  SelectInst *SAllocSize =
      SelectInst::Create (ILessThanSlotSize,
                          ConstantInt::get (Length->getType(),
                                            4,
                                            false),
                          BBinaryLog,
                          "size", BBAfterFindLog);

  BinaryOperator *BShlOne;
  BShlOne = BinaryOperator::Create (Instruction::Shl,
                                    ConstantInt::get (Length->getType(),1, false),
                                    SAllocSize,
                                    "shl_one",
                                    BBAfterFindLog);

  BinaryOperator *BSubOne;
  BSubOne = BinaryOperator::Create (Instruction::Sub,
                                    BShlOne,
                                    ConstantInt::get (BShlOne->getType(),1, false),
                                    "sub_one",
                                    BBAfterFindLog);
  BinaryOperator *BInv;
  BInv = BinaryOperator::Create (Instruction::Xor,
                                 BSubOne,
                                 ConstantInt::get (BSubOne->getType(), -1, false),
                                 "inv",
                                 BBAfterFindLog);
  BinaryOperator *BObjStart;
  BObjStart = BinaryOperator::Create (Instruction::And,
                                      Ptr,
                                      BInv,
                                      "obj_start",
                                      BBAfterFindLog);

  BinaryOperator *BIndex;
  BIndex = BinaryOperator::Create (Instruction::LShr,
                                   BObjStart,
                                   ConstantInt::get (BObjStart->getType(), 4, false),
                                   "index",
                                   BBAfterFindLog);
  BinaryOperator *BFixedSize;
  BFixedSize = BinaryOperator::Create (Instruction::Sub,
                                       SAllocSize,
                                       ConstantInt::get (SAllocSize->getType(), 4, false),
                                       "fixedsize",
                                       BBAfterFindLog);

  BinaryOperator *BRange;
  BRange = BinaryOperator::Create (Instruction::Shl,
                                   ConstantInt::get (SAllocSize->getType(), 1, false),
                                   BFixedSize,
                                   "range",
                                   BBAfterFindLog);

  GlobalVariable *GV = M->getGlobalVariable("__baggybounds_size_table_begin");
  LoadInst *TBL = new LoadInst(GV, "tbl", BBAfterFindLog);

  // Get the pointer to the actual slot size.
  ArrayRef<Value *> ARefTableBase (BIndex);
  GetElementPtrInst *GEPI = GetElementPtrInst::Create (Type::getInt8Ty(M->getContext()),
                                                       TBL,
                                                       ARefTableBase,
                                                       "index",
                                                       BBAfterFindLog);

  Function * Memset = cast<Function>(M->getFunction ("llvm.memset.p0i8.i32"));
  std::vector<Value *> args;

  CastInst *CAllocSize =
      CastInst::CreateIntegerCast (SAllocSize,
                                   Type::getInt8Ty(M->getContext()),
                                   false,
                                   "casted", BBAfterFindLog);
  CastInst *CRange =
      CastInst::CreateIntegerCast (BRange,
                                   Type::getInt32Ty(M->getContext()),
                                   false,
                                   "casted", BBAfterFindLog);

  const DataLayout & TD = M->getDataLayout();
  args.push_back (GEPI);
  args.push_back (CAllocSize);
  args.push_back (CRange);
  args.push_back (ConstantInt::get(Type::getInt32Ty(M->getContext()),
                                   TD.getABITypeAlignment(
                                       Type::getInt8Ty(M->getContext()))));
  args.push_back (ConstantInt::get(Type::getInt1Ty(M->getContext()), 0));
  CallInst::Create (Memset, args, "", BBAfterFindLog);

  return BBAfterFindLog;
}


//
// Function: createPoolRegisterBodyFor
//
// Description:
//  This function create the implementation of pool_register_debug function
//
// Inputs:
//  F - The function to be implemented
//
template <bool T>
bool
llvm::InlineBBCRuntimeFunctions<T>::createPoolRegisterBodyFor (Function * F) {
  //
  // If the function does not exist, do nothing.
  //
  if (!F) return false;
  //
  // If the function has a body, do nothing.
  //
  if (!(F->isDeclaration())) return false;

  LLVMContext &Context = F->getContext();

  //
  // Create an entry block that will perform the comparisons and branch either
  // to the success block or the fault block.
  //
  BasicBlock *EntryBB = BasicBlock::Create (Context, "entry", F);
  //
  // Create a basic block that just returns.
  //
  BasicBlock *GoodBB = BasicBlock::Create (Context, "good", F);
  ReturnInst::Create (F->getContext(), GoodBB);

  BasicBlock *NumBytesNotZeroBB = BasicBlock::Create(Context,
                                                     "num_bytes_not_zero",
                                                     F);

  BasicBlock *AllocaPtrNotNullBB = BasicBlock::Create(Context,
                                                      "alloca_ptr_not_null",
                                                      F);

  Function::arg_iterator arg = F->arg_begin();

  Value *Pool = castToInt (arg++, EntryBB);
  Value *AllocaPtr = arg, *AllocaPtrInt = castToInt (arg++, EntryBB);
  Value *NumBytes = arg++;
  Value *Tag = arg++;
  Value *SourceFilep = arg++;
  Value *LineNo = arg;

  ICmpInst * CompareNumBytes = new ICmpInst (*EntryBB,
                                             CmpInst::ICMP_EQ,
                                             NumBytes,
                                             ConstantInt::get (NumBytes->getType(), 0, false),
                                             "cmp_num_bytes_zero");

  BranchInst::Create (GoodBB, NumBytesNotZeroBB, CompareNumBytes, EntryBB);

  ICmpInst * CompareAllocaPtr = new ICmpInst (*NumBytesNotZeroBB,
                                              CmpInst::ICMP_EQ,
                                              AllocaPtrInt,
                                              ConstantInt::get(AllocaPtrInt->getType(), 0, false),
                                              "cmp_alloca_ptr_null");

  BranchInst::Create (GoodBB, AllocaPtrNotNullBB, CompareAllocaPtr, NumBytesNotZeroBB);


  CastInst *CILength =
      CastInst::CreateIntegerCast (NumBytes,
                                   AllocaPtrInt->getType(),
                                   false,
                                   "casted", AllocaPtrNotNullBB);

  BasicBlock* ReturnBB =
      insertInternalRegister(AllocaPtrInt, CILength, AllocaPtrNotNullBB);
  ReturnInst::Create (Context, ReturnBB);

  F->setLinkage (GlobalValue::InternalLinkage);
  return true;
}

static
BasicBlock *
insertInternalUnregister (Value *Ptr ,
                          BasicBlock *GoodBB,
                          BasicBlock *BB) {
  //
  // Assert that the caller is giving us a casted integer value.
  //
  assert (isa<IntegerType>(Ptr->getType()));

  Module *M = BB->getModule();

  BasicBlock * BBElementNotZero =
      BasicBlock::Create (M->getContext(),
                          "metatable_element_not_zero",
                          BB->getParent());

  BinaryOperator *BIndex;
  BIndex = BinaryOperator::Create (Instruction::LShr,
                                   Ptr,
                                   ConstantInt::get (Ptr->getType(),4, false),
                                   "size",
                                   BB);

  GlobalVariable *GV = M->getGlobalVariable("__baggybounds_size_table_begin");
  LoadInst *TBL = new LoadInst(GV, "tbl", BB);

  // Get the pointer to the actual slot size.
  ArrayRef<Value *> ARefTableBase (BIndex);
  GetElementPtrInst *GEPI = GetElementPtrInst::Create (Type::getInt8Ty(M->getContext()),
                                                       TBL,
                                                       ARefTableBase,
                                                       "index",
                                                       BB);
  LoadInst * LObjSizeBeforeCast = new LoadInst (GEPI,
                                                "obj_size",
                                                BB);
  CastInst *LObjSize =
      CastInst::CreateIntegerCast (LObjSizeBeforeCast,
                                   Type::getInt64Ty(M->getContext()),
                                   false,
                                   "casted", BB);

  ICmpInst * ICmpCompareZero = new ICmpInst (*BB,
                                             CmpInst::ICMP_EQ,
                                             LObjSize,
                                             ConstantInt::get (LObjSize->getType(), 0, false),
                                             "cmp_zero");

  BranchInst::Create (GoodBB,
                      BBElementNotZero,
                      ICmpCompareZero,
                      BB);



  BinaryOperator *BSize;
  BSize = BinaryOperator::Create (Instruction::Shl,
                                  ConstantInt::get (LObjSize->getType(),1, false),
                                  LObjSize,
                                  "size",
                                  BBElementNotZero);
  BinaryOperator *BSizeSubOne;
  BSizeSubOne = BinaryOperator::Create (Instruction::Sub,
                                        BSize,
                                        ConstantInt::get (BSize->getType(),1, false),
                                        "sub_one",
                                        BBElementNotZero);
  BinaryOperator *BInv;
  BInv = BinaryOperator::Create (Instruction::Xor,
                                 BSizeSubOne,
                                 ConstantInt::get (BSize->getType(), -1, false),
                                 "inv",
                                 BBElementNotZero);
  BinaryOperator *BBase;
  BBase = BinaryOperator::Create (Instruction::And,
                                  Ptr,
                                  BInv,
                                  "inv",
                                  BBElementNotZero);

  BinaryOperator *BIndexMemset;
  BIndexMemset = BinaryOperator::Create (Instruction::LShr,
                                  BBase,
                                  ConstantInt::get (BSize->getType(), 4, false),
                                  "indexmemset",
                                  BBElementNotZero);

  BinaryOperator *BFixedSize;
  BFixedSize = BinaryOperator::Create (Instruction::Sub,
                                       LObjSize,
                                       ConstantInt::get (LObjSize->getType(), 4, false),
                                       "fixedsize",
                                       BBElementNotZero);

  BinaryOperator *BRange;
  BRange = BinaryOperator::Create (Instruction::Shl,
                                   ConstantInt::get (LObjSize->getType(), 1, false),
                                   BFixedSize,
                                   "range",
                                   BBElementNotZero);


  ArrayRef<Value *> ARefTableBaseMemset (BIndexMemset);
  GetElementPtrInst *GEPIMemset = GetElementPtrInst::Create (Type::getInt8Ty(M->getContext()),
                                                             TBL,
                                                             ARefTableBaseMemset,
                                                             "index",
                                                             BBElementNotZero);


  Function * Memset = cast<Function>(M->getFunction ("llvm.memset.p0i8.i32"));
  std::vector<Value *> args;

  ConstantInt *CAllocSize = ConstantInt::get (Type::getInt8Ty(M->getContext()),
                                              0, false);
  CastInst *CRange =
      CastInst::CreateIntegerCast (BRange,
                                   Type::getInt32Ty(M->getContext()),
                                   false,
                                   "casted", BBElementNotZero);


  args.push_back (GEPIMemset);
  args.push_back (CAllocSize);
  args.push_back (CRange);
  const DataLayout & TD = M->getDataLayout();
  args.push_back (ConstantInt::get(Type::getInt32Ty(M->getContext()),
                                   TD.getABITypeAlignment(
                                       Type::getInt8Ty(M->getContext()))));
  args.push_back (ConstantInt::get(Type::getInt1Ty(M->getContext()), 0));
  CallInst::Create (Memset, args, "", BBElementNotZero);

  return BBElementNotZero;
}



//
// Function: createPoolUnregisterBodyFor
//
// Description:
//  This function create the implementation of pool_unregister_debug function
//
// Inputs:
//  F - The function to be implemented
//
template <bool T>
bool
llvm::InlineBBCRuntimeFunctions<T>::createPoolUnregisterBodyFor(Function * F) {

  //
  // If the function does not exist, do nothing.
  //
  if (!F) return false;

  //
  // If the function has a body, do nothing.
  //
  if (!(F->isDeclaration())) return false;

  LLVMContext &Context = F->getContext();

  //
  // Create an entry block that will perform the comparisons and branch either
  // to the success block or the fault block.
  //
  BasicBlock *EntryBB = BasicBlock::Create (Context, "entry", F);
  //
  // Create a basic block that just returns.
  //
  BasicBlock *GoodBB = BasicBlock::Create (Context, "good", F);
  ReturnInst::Create (F->getContext(), GoodBB);

  BasicBlock *AllocaPtrNotNullBB = BasicBlock::Create(Context,
                                                      "alloca_ptr_not_null",
                                                      F);

  Function::arg_iterator arg = F->arg_begin();

  Value *Pool = castToInt (arg++, EntryBB);
  Value *AllocaPtr = arg, *AllocaPtrInt = castToInt (arg++, EntryBB);
  Value *Tag = arg++;
  Value *SourceFilep = arg++;
  Value *LineNo = arg;

  ICmpInst * CompareAllocaPtr = new ICmpInst (*EntryBB,
                                              CmpInst::ICMP_EQ,
                                              AllocaPtrInt,
                                              ConstantInt::get(AllocaPtrInt->getType(), 0, false),
                                              "cmp_alloca_ptr_null");

  BranchInst::Create (GoodBB, AllocaPtrNotNullBB, CompareAllocaPtr, EntryBB);


  BasicBlock *BBElementNotZero
      = insertInternalUnregister(AllocaPtrInt, GoodBB, AllocaPtrNotNullBB);
  ReturnInst::Create (F->getContext(), BBElementNotZero);

  F->setLinkage (GlobalValue::InternalLinkage);
  return true;
}

template <bool T>
bool
llvm::InlineBBCRuntimeFunctions<T>::runOnModule (Module &M) {
  createGlobalDeclarations (M);
  createPoolCheckUIBodyFor (M.getFunction("poolcheckui_debug"));
  createBoundsCheckUIBodyFor (M.getFunction("boundscheckui_debug"));
  createPoolRegisterBodyFor (M.getFunction("pool_register_debug"));
  createPoolRegisterBodyFor (M.getFunction("pool_register_stack_debug"));
  createPoolRegisterBodyFor (M.getFunction("pool_register_global_debug"));
  createPoolUnregisterBodyFor (M.getFunction("pool_unregister_debug"));
  createPoolUnregisterBodyFor (M.getFunction("pool_unregister_stack_debug"));

  inlineCheck (M.getFunction ("poolcheckui_debug"));
  inlineCheck (M.getFunction ("boundscheckui_debug"));
  inlineCheck (M.getFunction ("pool_register_debug"));
  inlineCheck (M.getFunction ("pool_register_stack_debug"));
  inlineCheck (M.getFunction ("pool_register_global_debug"));
  inlineCheck (M.getFunction ("pool_unregister_debug"));
  inlineCheck (M.getFunction ("pool_unregister_stack_debug"));
  return true;
}
