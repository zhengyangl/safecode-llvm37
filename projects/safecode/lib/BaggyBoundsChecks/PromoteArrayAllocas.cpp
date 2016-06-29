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

//
// Method: createProtos()
//
// Description:
//  Insert free and malloc function prototypes in a module.
//
// Input:
//  M - module to be inserted
//
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

//
// Function: transformArrayAlloca()
//
// Description:
//  Rewrite Array Allocation to Malloc.
//
// Input:
//  A - Alloca Instruction to be transformed.
//
// Output:
//  The transformed malloc instruction.
//
Instruction *
PromoteArrayAllocas::transformArrayAlloca (AllocaInst & A) {
  Value *TypeSize = ConstantInt::get (Int64Type, TD->getTypeAllocSize (A.getAllocatedType()));
  Instruction * MallocInsertPt = &A;
  Value *ArrayLength = A.getOperand(0);

  // If the type of ArrayLength is not i64, cast it to i64.
  if (ArrayLength->getType() != Int64Type) {
    ArrayLength = castTo (ArrayLength,
                          Int64Type,
                          ArrayLength->getName()+".casted",
                          MallocInsertPt);
  }

  //
  // Insert a mul instruction to calculate the actuall size of allocation.
  //   ActuallSize = TypeSize * ArrayLength
  //
  Instruction * ActualSize = BinaryOperator::Create (Instruction::Mul,
                                                     TypeSize,
                                                     ArrayLength,
                                                     "actualsize",
                                                     MallocInsertPt);

  // Insert the malloc call
  ArrayRef<Value *> MallocArgs (ActualSize);
  CallInst *MallocCall = CallInst::Create (malloc, MallocArgs, "", MallocInsertPt);

  // Cast the output of malloc to fit the original alloca type.
  Instruction * CastedMallocCall = castTo (MallocCall,
                                           A.getType(),
                                           MallocCall->getName()+".casted",
                                           MallocInsertPt);

  // Replace all uses of alloca with casted malloc return value.
  A.replaceAllUsesWith (CastedMallocCall);

  promoteArrayAllocas ++;
  return MallocCall;
}

//
// Function: insertFreeBeforeLeavingFunction()
//
// Description:
//  Find all of the return/resume points of the function. Insert a free on each
//  point. If LoadInstInsertion is set to true, then a load instruction is inserted
//  to get the actual pointer.
//
// Input:
//  Inst - The instruction to be freed
//  LoadInstInsertion - If true, then a MallocHelper is passed as Inst, a load instruction
//                      is inserted to get the actual address of the allocated memory. If
//                      false, then directly pass Inst as argument of free.
// Output:
//  0 - No free instruction inserted
//  1 - One or more free instruction inserted
//
bool
PromoteArrayAllocas::insertFreeBeforeLeavingFunction (Instruction * Inst,
                                                      bool LoadInstInsertion) {
  bool isInserted = false;
  BasicBlock *CurrentBlock = Inst->getParent();
  Function * F = CurrentBlock->getParent();

  // Iterate each basic blocks in the function, collect all free insertion points.
  std::vector<Instruction*> FreePoints;
  for (Function::iterator BB = F->begin(), E = F->end(); BB != E; ++BB)
    if (isa<ReturnInst>(BB->getTerminator()) ||
        isa<ResumeInst>(BB->getTerminator()))
      FreePoints.push_back(BB->getTerminator());

  std::vector<Instruction*>::iterator fpI = FreePoints.begin(),
                                      fpE = FreePoints.end();
  for (; fpI != fpE ; ++ fpI) {
    Instruction *InsertPt = *fpI;
    if(LoadInstInsertion)
      //
      // If MallocHelper is installed, then we need to insert a load instruction to
      // get the actual free pointer.
      //
      Inst = new LoadInst (Inst, Inst->getName() + ".loaded", InsertPt);

    ArrayRef<Value *> args(Inst);
    CallInst::Create (free, args, "", InsertPt);
    isInserted = true;
  }
  return isInserted;
}

//
// Function: installMallocHelper()
//
// Description:
//  This function installs the malloc helper instructions to the mallocs which is not
//  in the entry blocks. The malloc helper is the stack memory to help store the return
//  value of a malloc call.
//
//  A piece of stack memory will be allocated for each of not-in-entryblock malloc calls.
//  At the entry block, these memory are initialized to NULL pointer. Each of the stack
//  memory will store the result of corresponding malloc return value if that malloc is
//  called on the execution, or leave it blank if that malloc is not called. If malloc is
//  called, then the address of malloc allocated memory must be stored, so we can load
//  the alloca, pass the result to free and release the allocated memory. If malloc is not
//  called, then the stored address is not modified. Since free a NULL pointer will cause no
//  actions according to C standard, 7.20.3.2/2 from ISO-IEC 9899. We can also load the
//  alloca, pass the NULL pointer to free and do nothing.
//
//  Three instructions are inserted in this function.
//
//  1. A alloca instruction. This will allocate the stack memory which is used to store
//     the result of malloc.
//  2. A store instruction. This instruction will be inserted to the very beginning of
//     the entry block. This instruction is used to initialize the alloca to NULL pointer.
//  3. A store instruction. This instruction will be inserted just after the malloc call.
//     We use this instruction to store the result pointer of malloc call.
//
// Input:
//  MallocInst - The malloc result value to be stored.
//
// Output:
//  The MallocHelper.
//
Instruction *
PromoteArrayAllocas::installMallocHelper (Instruction * MallocInst) {
  BasicBlock * CurrentBlock = MallocInst->getParent();
  Function   * F = CurrentBlock->getParent();
  Module     * M = CurrentBlock->getModule();
  BasicBlock & EntryBlock = F->getEntryBlock();

  AllocaInst * MallocHelper = new AllocaInst (getVoidPtrType(*M),
                                              "mallochelper",
                                              EntryBlock.getFirstInsertionPt());

  // Initialize MallocHelper with a NULL pointer
  Instruction * insertPt = ++EntryBlock.getFirstInsertionPt();
  new StoreInst(ConstantPointerNull::get(getVoidPtrType(*M)),
                MallocHelper,
                false,
                insertPt);

  // Store the malloc return value to MallocHelper
  (new StoreInst (MallocInst,
                  MallocHelper,
                  false))->insertAfter(MallocInst);

  return MallocHelper;
}

//
// Method: visitAllocaInst()
//
// Description:
//
//  Visit all alloca instructions in a module. Ignore all single element allocas and allocas
//  whose length can be determined.
//
//  Then for the rest of allocas, we check if it is in entry blocks.
//
//  For the allocas in the entry block, since entry block dominates all the blocks in the
//  function, we simply insert a free at each return and resume instruction.
//
//  For the allocas which is not in the entry block,
//  1. Insert an alloca in the entry basic block that allocates a pointer on the stack.
//  2. Add a store instruction at the end of the entry basic block that initializes that
//     pointer to a null pointer.
//  3. After the new malloc call, insert a store instruction to store the return value
//     of malloc on the stack.
//  4. Before every ret and unwind instruction, insert code to load the pointer from
//     the stack and free it.
//  Step 1-3 is done by calling installMallocHelper function.
//
// Input:
//  A - the alloca to be processed
//
void
PromoteArrayAllocas::visitAllocaInst(AllocaInst &A)
{
  if(!A.isArrayAllocation() || isa<ConstantInt>(A.getOperand(0)))
    return;

  Instruction * I = transformArrayAlloca(A);
  BasicBlock * Parent = A.getParent();
  bool isInserted = false;
  // Check whether current block is in entry block or not.
  if(Parent == &Parent->getParent()->front())
    // Current block is entry block. Insert free at each return/resume point.
    isInserted = insertFreeBeforeLeavingFunction(I, false);
  else
  {
    // Current block is not entry block. Install a Malloc Helper to this malloc.
    Instruction * MallocReturnVal = installMallocHelper (I);
    // Set LoadInstInsertion to true. At the return/resume point, we first insert a load
    // instruction to get the malloc return value, then insert a free call to it.
    isInserted = insertFreeBeforeLeavingFunction (MallocReturnVal, true);
  }
  if (!isInserted) missingFrees ++;

  Parent->getInstList().erase(A);
}

//
// Function runOnModule()
//
// Description:
//  Prepare the Data Layout information. Initialize VoidType and Int64Type. Prepare the
//  malloc/free prototype. Call the InstVisitor to promote the allocas.
//
bool
PromoteArrayAllocas::runOnModule (Module & M) {
  TD       = &M.getDataLayout();
  // Get needed LLVM types.
  VoidType  = Type::getVoidTy(getGlobalContext());
  Int64Type = IntegerType::getInt64Ty(getGlobalContext());

  // Add protype for run-time functions.
  createProtos(M);

  visit(M);
  return true;
}

} //end namespace llvm

