//===- InlineBBRuntimeFunctions.cpp - Inline BBAC RuntimeFunctions--------- --//
//
//                          The SAFECode Compiler
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This pass replaces calls to bbac runtime functions within inline code to perform
// the check.  It is designed to provide the advantage of libLTO without libLTO.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "inline_bb_runtime_functions"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "safecode/InlineBBRuntimeFunctions.h"
#include "safecode/Utility.h"
#include "safecode/Runtime/BBMetaData.h"
#include "llvm/Transforms/Utils/Cloning.h"

namespace {
STATISTIC (InlinedBBChecks, "Number of BBAC Runtime Functions Inlined");
}

namespace llvm {
char InlineBBRuntimeFunctions::ID = 0;
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
bool
llvm::InlineBBRuntimeFunctions::inlineCheck (Function * F) {
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
    ++ InlinedBBChecks;
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
// Function: insertGetBBLength()
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
insertGetBBLength (Value *Ptr,
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
// Function: insertGetBBRange()
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
insertGetBBRange (Value *Ptr, Value *Length ,BasicBlock *BB) {
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
  BinaryOperator *BShrOne;
  BShrOne = BinaryOperator::Create (Instruction::Shl,
                                    ConstantInt::get (Length->getType(),1, false),
                                    Length,
                                    "shl_one",
                                    BB);
  BinaryOperator *BSubOne;
  BSubOne = BinaryOperator::Create (Instruction::Sub,
                                    BShrOne,
                                    ConstantInt::get (BShrOne->getType(),1, false),
                                    "sub_one",
                                    BB);
  BinaryOperator *BInv;
  BInv = BinaryOperator::Create (Instruction::Xor,
                                 BSubOne,
                                 ConstantInt::get (BSubOne->getType(), -1, false),
                                 "inv",
                                 BB);
  BinaryOperator *BObjStart;
  BObjStart = BinaryOperator::Create (Instruction::And,
                                      Ptr,
                                      BInv,
                                      "obj_start",
                                      BB);

  //
  // Calculate the address of BBMetaData.
  //  SlotEnd = ObjStart + (1 << e);
  //  MetaData = SlotEnd - sizeof(BBMetaData);
  //
  BinaryOperator *BSlotEnd;
  BSlotEnd = BinaryOperator::Create (Instruction::Add,
                                     BShrOne,
                                     BObjStart,
                                     "slot_end",
                                     BB);

  BinaryOperator *BMetaData;
  BMetaData = BinaryOperator::Create (Instruction::Sub,
                                      BSlotEnd,
                                      ConstantInt::get(BSlotEnd->getType(),
                                                       sizeof(BBMetaData), false),
                                      "metadata",
                                      BB);

  //
  // Define the data structure of BBMetaData
  //  struct BBMetaData {
  //    unsigned int size;
  //    void *pool;
  //  };
  //
  std::vector<Type *> BBMetaDataFields;
  BBMetaDataFields.push_back(Type::getInt32Ty(M->getContext()));
  BBMetaDataFields.push_back(Type::getInt8PtrTy(M->getContext()));
  StructType *BBMetaDataTy;
  BBMetaDataTy = StructType::create(M->getContext(),
                                    BBMetaDataFields,
                                    "BBMetaData");
  PointerType * BBMetaDataPtrTy = PointerType::get(BBMetaDataTy, 0);

  std::vector<Value *> ArefMD;
  ArefMD.push_back (ConstantInt::get(Type::getInt32Ty(M->getContext()),0, false));
  ArefMD.push_back (ConstantInt::get(Type::getInt32Ty(M->getContext()),0, false));

  //
  // Dereference the size field of BBMetaData
  //  BBMetaData *data = (BBMetaData*)(ObjStart + (1<<e) - sizeof(BBMetaData));
  //
  Instruction * MetaDataIntPtr = new IntToPtrInst(BMetaData,
                                                  Type::getInt8PtrTy(M->getContext()),
                                                  "metadata_iptr",
                                                  BB);
  BitCastInst * MetaDataPtr = new BitCastInst (MetaDataIntPtr,
                                               BBMetaDataPtrTy,
                                               "metadata_ptr",
                                               BB);

  //
  // Get the upper bound
  //  uintptr_t ObjEnd = ObjStart + data->size - 1;
  //
  GetElementPtrInst *ObjSizePtr = GetElementPtrInst::CreateInBounds (BBMetaDataTy,
                                                                     MetaDataPtr,
                                                                     ArefMD,
                                                                     "obj_size_ptr",
                                                                     BB);
  LoadInst * LObjSize = new LoadInst (ObjSizePtr,
                                     "obj_size",
                                     BB);
  Value * LObjSizeCasted = castTo(LObjSize, Type::getInt64Ty(M->getContext()),
                                  LObjSize->getName() + ".casted",
                                  BB);

  BinaryOperator *BObjSizeSubOne;
  BObjSizeSubOne = BinaryOperator::Create (Instruction::Sub,
                                           LObjSizeCasted,
                                           ConstantInt::get (LObjSizeCasted->getType(),1, false),
                                           "obj_size_sub_one",
                                           BB);

  BinaryOperator *BObjEnd;
  BObjEnd = BinaryOperator::Create (Instruction::Add,
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
//  This function inserts instructions for poolcheckui function. All the instructions
//  are inserted to basic block BB.
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

  BasicBlock * NotPassBBLengthCheckBB = BasicBlock::Create (M->getContext(),
                                                            "not_pass_bblength_check",
                                                            BB->getParent());

  //
  // Get Memory Object Bounds from Baggy Bounds Size Table.
  //
  Value * BBLength = insertGetBBLength (Ptr, BB, GoodBB, NotPassBBLengthCheckBB);
  std::tuple<Value*, Value*> BBRange = insertGetBBRange(Ptr, BBLength, NotPassBBLengthCheckBB);
  Value *ObjStart = std::get<0>(BBRange);
  Value *ObjEnd = std::get<1>(BBRange);

  //
  // Get the end of the memory object, aka NodeEnd.
  // uintptr_t NodeEnd = (uintptr_t)Node + length -1;
  //
  BinaryOperator *BLenSubOne;
  BLenSubOne = BinaryOperator::Create (Instruction::Sub,
                                       Len,
                                       ConstantInt::get (Len->getType(), 1, false),
                                       "len_sub_one",
                                       NotPassBBLengthCheckBB);

  BinaryOperator *BNodeEnd;
  BNodeEnd = BinaryOperator::Create (Instruction::Add,
                                     Ptr,
                                     BLenSubOne,
                                     "node_end",
                                     NotPassBBLengthCheckBB);

  //
  // Compare the NodeEnd with the bounds of the memory object. The original compare code as
  // following, we simplify them as following.
  //
  //    !((ObjStart <= NodeEnd) &&  (NodeEnd <= ObjEnd))
  // ->  !(ObjStart <= NodeEnd) || !(NodeEnd <= ObjEnd)
  // ->   (ObjStart >  NodeEnd) ||  (NodeEnd >  ObjEnd)
  //
  ICmpInst * ICmpCompareLHS = new ICmpInst (*NotPassBBLengthCheckBB,
                                            CmpInst::ICMP_UGT,
                                            ObjStart,
                                            BNodeEnd,
                                            "cmp_lhs");
  ICmpInst * ICmpCompareRHS = new ICmpInst (*NotPassBBLengthCheckBB,
                                            CmpInst::ICMP_UGT,
                                            BNodeEnd,
                                            ObjEnd,
                                            "cmp_rhs");
  BinaryOperator *BOEmitReport = BinaryOperator::Create (Instruction::Or,
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
//  This function inserts instructions for _barebone_pointer_in_bounds function. All the
//  instructions are inserted to basic block BB.
//
// Inputs:
//  Src - The base pointer
//  Dst - The pointer to be accessed.
//  BB - The basic block to be inserted
//  GoodBB - jump to this basic block if the program passes the check
//  NotPassIsPointerInBoundsBB - jump to this basic block if the program does not pass the check
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
  BasicBlock * NotPassBBLengthCheckBB = BasicBlock::Create (M->getContext(),
                                                            "not_pass_bb_length_check",
                                                            BB->getParent());
  // Get the Object BB Length from Baggy Bounds size table.
  Value * BBLength = insertGetBBLength (Source, BB, GoodBB, NotPassBBLengthCheckBB);

  // Get the bounds with the input address Source and BB Length.
  std::tuple<Value*, Value*> BBRange = insertGetBBRange(Source, BBLength, NotPassBBLengthCheckBB);
  Value *ObjStart = std::get<0>(BBRange);
  Value *ObjEnd = std::get<1>(BBRange);

  //
  // Compare the Source and Dest with the bounds of that memory object.
  //
  // The original runtime code is as following.
  //   return !(begin <= Source && Source < end && begin <= Dest && Dest < end);
  //
  // Since our ObjEnd calculated by insertGetBBRange is equals to (end - 1), we need
  // turn the < to <= on Source < end and Dest < end. The final compares is as following.
  //
  // !((ObjStart <= Source) && (Source <= ObjEnd) && (ObjStart <= Dest ) && (Dest <= end))
  //
  ICmpInst * ICmpBeginLESource = new ICmpInst (*NotPassBBLengthCheckBB,
                                               CmpInst::ICMP_ULE,
                                               ObjStart,
                                               Source,
                                               "cmp_begin_le_source");
  ICmpInst * ICmpSourceLTEnd = new ICmpInst (*NotPassBBLengthCheckBB,
                                             CmpInst::ICMP_ULE,
                                             Source,
                                             ObjEnd,
                                             "cmp_source_lt_end");
  ICmpInst * ICmpBeginLEDest = new ICmpInst (*NotPassBBLengthCheckBB,
                                             CmpInst::ICMP_ULE,
                                             ObjStart,
                                             Dest,
                                             "cmp_begin_le_dest");
  ICmpInst * ICmpDestLTEnd = new ICmpInst (*NotPassBBLengthCheckBB,
                                           CmpInst::ICMP_ULE,
                                           Dest,
                                           ObjEnd,
                                           "cmp_dest_lt_end");

  // Combine the compares with AND operators.
  BinaryOperator *BOCompareLeftHalf = BinaryOperator::Create (Instruction::And,
                                                         ICmpBeginLESource,
                                                         ICmpSourceLTEnd,
                                                         "compare_left_half",
                                                         NotPassBBLengthCheckBB);

  BinaryOperator *BOCompareRightHalf = BinaryOperator::Create (Instruction::And,
                                                               ICmpBeginLEDest,
                                                               ICmpDestLTEnd,
                                                               "compare_right_half",
                                                               NotPassBBLengthCheckBB);

  BinaryOperator *BOCompare = BinaryOperator::Create (Instruction::And,
                                                      BOCompareLeftHalf,
                                                      BOCompareRightHalf,
                                                      "compare",
                                                      NotPassBBLengthCheckBB);

  //
  // If compare fails, aka neither Source nor Dest is in range, then we jump to
  // NotPassIsPointerInBoundsBB, otherwise, we jump to GoodBB and simply return the Dest
  // pointer.
  //
  BranchInst::Create (GoodBB, NotPassIsPointerInBoundsBB, BOCompare, NotPassBBLengthCheckBB);
}

//
// Function: createGlobalDeclarations()
//
// Description:
//  This function insert the declaration of baggy bounds size table pointer as a GlobalVariable
//
// Inputs:
//  M - The module to be inserted
//
bool
llvm::InlineBBRuntimeFunctions::createGlobalDeclarations (Module & M) {
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
bool
llvm::InlineBBRuntimeFunctions::createPoolCheckUIBodyFor (Function * F) {
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

  BasicBlock *NotPassZeroLenCheckBB = BasicBlock::Create (Context,
                                                          "not_pass_zero_len_check", F);

  BasicBlock *PassRewrittenCheckBB = BasicBlock::Create (Context,
                                                         "pass_rewritten_check", F);

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
  insertIsRewrittenPtr (Node, NotPassZeroLenCheckBB, PassRewrittenCheckBB, FaultBB);
  insertBBPoolCheck(Node, Length, PassRewrittenCheckBB, GoodBB, FaultBB);

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
bool
llvm::InlineBBRuntimeFunctions::createBoundsCheckUIBodyFor (Function * F) {
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
  BasicBlock *EntryBB = BasicBlock::Create (Context, "entry", F);
  //
  // Create a basic block that just returns.
  //
  BasicBlock *GoodBB = BasicBlock::Create (Context, "good", F);

  BasicBlock *NotPassIsSrcDstEqualCheckBB = BasicBlock::Create(Context,
                                                               "not_pass_is_src_dst_equal_check",
                                                               F);

  BasicBlock *NotPassIsPointerInBoundsBB = BasicBlock::Create(Context,
                                                              "not_pass_is_pointerinbounds_check",
                                                              F);

  Function::arg_iterator arg = F->arg_begin();

  Value *Pool = castToInt (arg++, EntryBB);
  Value *SourcePtr = arg, *Source = castToInt (arg++, EntryBB);
  Value *DestPtr = arg, *Dest = castToInt (arg++, EntryBB);

  ReturnInst::Create (F->getContext(), DestPtr, GoodBB);
  insertIsSrcDstEqualCheck (Source, Dest, EntryBB, GoodBB, NotPassIsSrcDstEqualCheckBB);
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
// Function: createPoolRegisterBodyFor
//
// Description:
//  This function create the implementation of pool_register_debug function
//
// Inputs:
//  F - The function to be implemented
//
bool
llvm::InlineBBRuntimeFunctions::createPoolRegisterBodyFor (Function * F) {
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

  Constant *FPoolRegisterDebug =
      F->getParent()->getOrInsertFunction("__sc_bb_src_poolregister",
                                          Type::getVoidTy(Context),
                                          Pool->getType(),
                                          AllocaPtr->getType(),
                                          NumBytes->getType(),
                                          Tag->getType(),
                                          SourceFilep->getType(),
                                          LineNo->getType(),
                                          NULL);

  Value* TmpArgArray[6];
  TmpArgArray[0] = Pool;
  TmpArgArray[1] = AllocaPtr;
  TmpArgArray[2] = NumBytes;
  TmpArgArray[3] = Tag;
  TmpArgArray[4] = SourceFilep;
  TmpArgArray[5] = LineNo;

  CallInst *CallFPoolRegisterDebug
      = CallInst::Create(FPoolRegisterDebug,
                         ArrayRef<Value*>(TmpArgArray, 6),
                         "",
                         AllocaPtrNotNullBB);
  ReturnInst::Create (Context, AllocaPtrNotNullBB);

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

  F->setLinkage (GlobalValue::InternalLinkage);
  return true;
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
bool
llvm::InlineBBRuntimeFunctions::createPoolUnregisterBodyFor (Function * F) {

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

  Constant *FPoolRegisterDebug =
      F->getParent()->getOrInsertFunction("__sc_bb_poolunregister",
                                          Type::getVoidTy(Context),
                                          Pool->getType(),
                                          AllocaPtr->getType(),
                                          Tag->getType(),
                                          SourceFilep->getType(),
                                          LineNo->getType(),
                                          NULL);

  Value* TmpArgArray[5];
  TmpArgArray[0] = Pool;
  TmpArgArray[1] = AllocaPtr;
  TmpArgArray[2] = Tag;
  TmpArgArray[3] = SourceFilep;
  TmpArgArray[4] = LineNo;

  CallInst *CallFPoolRegisterDebug
      = CallInst::Create(FPoolRegisterDebug,
                         ArrayRef<Value*>(TmpArgArray, 5),
                         "",
                         AllocaPtrNotNullBB);
  ReturnInst::Create (Context, AllocaPtrNotNullBB);

  ICmpInst * CompareAllocaPtr = new ICmpInst (*EntryBB,
                                              CmpInst::ICMP_EQ,
                                              AllocaPtrInt,
                                              ConstantInt::get(AllocaPtrInt->getType(), 0, false),
                                              "cmp_alloca_ptr_null");

  BranchInst::Create (GoodBB, AllocaPtrNotNullBB, CompareAllocaPtr, EntryBB);

  F->setLinkage (GlobalValue::InternalLinkage);
  return true;
}

bool
llvm::InlineBBRuntimeFunctions::runOnModule (Module &M) {
  createGlobalDeclarations (M);
  createPoolCheckUIBodyFor (M.getFunction("poolcheckui_debug"));
  createBoundsCheckUIBodyFor (M.getFunction("boundscheckui_debug"));
  createPoolRegisterBodyFor (M.getFunction("pool_register_debug"));
  createPoolUnregisterBodyFor (M.getFunction("pool_unregister_debug"));

  inlineCheck (M.getFunction ("poolcheckui_debug"));
  inlineCheck (M.getFunction ("boundscheckui_debug"));
  inlineCheck (M.getFunction ("pool_register_debug"));
  inlineCheck (M.getFunction ("pool_unregister_debug"));
  return true;
}
