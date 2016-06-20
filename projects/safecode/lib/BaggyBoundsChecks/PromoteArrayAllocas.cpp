//===- PromoteArrayAlloca.cpp - Promote array alloca instructions to malloc --//
//
//                          The SAFECode Compiler
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a pass that promotes array alloca instuction to malloc
// allocations.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "promotearrayalloca"

#include "safecode/Config/config.h"
#include "safecode/Utility.h"
#include "safecode/PromoteArrayAllocas.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/DominanceFrontier.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/LLVMContext.h"

#include <list>

namespace llvm {

STATISTIC (promoteArrayAllocas,  "Number of converted array allocas");
STATISTIC (missingFrees, "Number of frees that we didn't insert");

namespace {
static RegisterPass<PromoteArrayAllocas> paa
("promoteArrayAllocas", "Promote Array Allocas");
}

char PromoteArrayAllocas::ID = 0;

void
PromoteArrayAllocas::createProtos (Module & M) {
  ArrayRef<Type *> Arg (Int64Type);
  FunctionType *mallocTy = FunctionType::get (getVoidPtrType(M), Arg, false);
  malloc = M.getOrInsertFunction ("malloc", mallocTy);

  ArrayRef<Type *> FreeArgs (getVoidPtrType(M));
  FunctionType *freeTy = FunctionType::get (Type::getVoidTy(M.getContext()), FreeArgs, false);
  free = M.getOrInsertFunction ("free", freeTy);

  assert ((malloc != 0) && "No malloc function found!\n");
  assert ((free   != 0) && "No free   function found!\n");
}

// Transform Array Allocation to Malloc
Instruction *
PromoteArrayAllocas::transformArrayAlloca (AllocaInst & A) {
  uint64_t TypeSize = TD->getTypeAllocSize (A.getAllocatedType());
  Value *AllocSize = ConstantInt::get (Int64Type, TypeSize);
  Instruction * MallocInsertPt = &A;
  Value *ArraySize = A.getOperand(0);
  if (ArraySize->getType() != Int64Type) {
    ArraySize = castTo (ArraySize,
                        Int64Type,
                        ArraySize->getName()+".casted",
                        MallocInsertPt);
  }
  ArraySize = BinaryOperator::Create (Instruction::Mul, AllocSize,
                                      ArraySize, "arrayallocasizetmp",
                                      MallocInsertPt);
  ArrayRef<Value *> MallocArgs (ArraySize);
  CallInst *MallocCall = CallInst::Create (malloc, MallocArgs, "", MallocInsertPt);
  Instruction * CastedMallocCall = castTo (MallocCall,
                                           A.getType(),
                                           MallocCall->getName()+".casted",
                                           MallocInsertPt);

  A.replaceAllUsesWith (CastedMallocCall);
  promoteArrayAllocas ++;
  return MallocCall;
}

//
// There are two kinds of allocas: the allocas in the entry block and the allocas
// out of entry block. For the alloca in the entry block, simply insert the free
// at the end of the block.
//
bool
PromoteArrayAllocas::insertFreeForAllocaInEntryBlock (AllocaInst & A,
                                                      Instruction * MallocInst) {
  bool isInserted = false;
  BasicBlock *CurrentBlock = A.getParent();
  Function * F = CurrentBlock->getParent();
  std::vector<Instruction*> FreePoints;
  for (Function::iterator BB = F->begin(), E = F->end(); BB != E; ++BB)
    if (isa<ReturnInst>(BB->getTerminator()) ||
        isa<ResumeInst>(BB->getTerminator()))
      FreePoints.push_back(BB->getTerminator());

  std::vector<Instruction*>::iterator fpI = FreePoints.begin(),
                                      fpE = FreePoints.end();
  for (; fpI != fpE ; ++ fpI) {
    Instruction *InsertPt = *fpI;
    ArrayRef<Value *> args(MallocInst);
    CallInst::Create (free, args, "", InsertPt);
    isInserted = true;
  }
  return isInserted;
}

//
// For the allocas of of entry block, For 'Definations must dominate uses', we must ensure
// that the free() is dominated by the malloc().
//
bool
PromoteArrayAllocas::insertFreeForAllocaOutOfEntryBlock (AllocaInst & A,
                                                         Instruction * MallocInst) {
  BasicBlock *CurrentBlock = A.getParent();
  Function * F = CurrentBlock->getParent();
  DominanceFrontier * dfmt = &getAnalysis<DominanceFrontier>(*F);
  DominatorTree     * domTree = &getAnalysis<DominatorTreeWrapperPass>(*F).getDomTree();

  DominanceFrontier::const_iterator it = dfmt->find(CurrentBlock);
  if (it != dfmt->end()) {
    const DominanceFrontier::DomSetType &S = it->second;
    if (S.size() > 0) {
      DominanceFrontier::DomSetType::iterator pCurrent = S.begin(), pEnd = S.end();
      for (; pCurrent != pEnd; ++pCurrent) {
        BasicBlock *frontierBlock = *pCurrent;
        // One of its predecessors is dominated by CurrentBlock;
        // need to insert a free in that predecessor
        for (pred_iterator SI = pred_begin(frontierBlock),
                 SE = pred_end(frontierBlock);
             SI != SE; ++SI) {
          BasicBlock *predecessorBlock = *SI;
          if (domTree->dominates (predecessorBlock, CurrentBlock)) {
            // Get the terminator
            Instruction *InsertPt = predecessorBlock->getTerminator();
            ArrayRef<Value *> args(MallocInst);
            CallInst::Create (free, args, "", InsertPt);
          }
        }
      }
      return true;
    }
  }
  return insertFreeForAllocaInEntryBlock(A, MallocInst);
}

void
PromoteArrayAllocas::visitAllocaInst(AllocaInst &A)
{
  if(!A.isArrayAllocation() || isa<ConstantInt>(A.getOperand(0)))
    return;

  Instruction * I = transformArrayAlloca(A);
  BasicBlock * Parent = A.getParent();
  bool isInserted = false;
  if(Parent == &Parent->getParent()->front())
    isInserted = insertFreeForAllocaInEntryBlock(A, I);
  else
    isInserted = insertFreeForAllocaOutOfEntryBlock(A, I);

  if (!isInserted) missingFrees ++;

  Parent->getInstList().erase(A);
}

bool
PromoteArrayAllocas::runOnModule (Module & M) {
  TD       = &M.getDataLayout();
  //
  // Get needed LLVM types.
  //
  VoidType  = Type::getVoidTy(getGlobalContext());
  Int32Type = IntegerType::getInt32Ty(getGlobalContext());
  Int64Type = IntegerType::getInt64Ty(getGlobalContext());

  //
  // Add protype for run-time functions.
  //
  createProtos(M);

  visit(M);
  return true;
}

} //end namespace llvm

