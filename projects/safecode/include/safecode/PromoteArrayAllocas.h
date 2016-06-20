//===- PromoteArrayAlloca.h - Promote array alloca instructions to malloc ----//
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


#ifndef PROMOTE_ARRAY_ALLOCA_H
#define PROMOTE_ARRAY_ALLOCA_H


#include "safecode/Config/config.h"
#include "safecode/SAFECode.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Analysis/DominanceFrontier.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Pass.h"
#include <set>

namespace llvm {

//
// Pass: PromoteArrayAllocas
//
// Description:
//  This pass promotes array allocations to malloc allocations if necessary to
//  provide bbac runtime check support.
//

class PromoteArrayAllocas : public ModulePass,
                            public InstVisitor<PromoteArrayAllocas> {
  public:
    static char ID;
    PromoteArrayAllocas () : ModulePass (ID) {}
    const char *getPassName() const { return "Promote Array Allocas";}
    virtual bool runOnModule(Module &M);
    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.setPreservesCFG();
      AU.addRequired<DominanceFrontier>();
      AU.addRequired<DominatorTreeWrapperPass>();
    };

    void visitAllocaInst(AllocaInst &A);
  protected:
    Constant *malloc;
    Constant *free;
    void createProtos(Module & M);
    Instruction * transformArrayAlloca (AllocaInst & A);
    bool insertFreeForAllocaInEntryBlock(AllocaInst & A, Instruction * MallocInst);
    bool insertFreeForAllocaOutOfEntryBlock(AllocaInst &A, Instruction * MallocInst);
    const DataLayout * TD;

    Type * VoidType;
    Type * Int32Type;
    Type * Int64Type;
};

} //end namespace llvm
#endif
