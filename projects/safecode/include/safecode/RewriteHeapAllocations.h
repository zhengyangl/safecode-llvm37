//===- RewriteHeapAllocations.h - Rewrite Heap Allocation Functions ------- --//
// 
//                          The SAFECode Compiler
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This pass replace the malloc / calloc / realloc calls with __sc_bb_malloc /
// __sc_bb_calloc / __sc_bb_realloc calls.
//
//===----------------------------------------------------------------------===//


#ifndef REWRITEHEAPALLOCATIONS_H
#define REWRITEHEAPALLOCATIONS_H

#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

namespace llvm {

//
// Pass: RewriteHeapAllocations
//
// Description:
//  This pass replace the malloc / calloc / realloc calls with __sc_bb_malloc /
//  __sc_bb_calloc / __sc_bb_realloc calls.
//
class RewriteHeapAllocations : public ModulePass {
  public:
    static char ID;
    RewriteHeapAllocations() : ModulePass(ID) {}
    const char * getPassName() const { return "Rewrite Heap Allocations pass"; }
    virtual bool runOnModule (Module & M);
    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.setPreservesCFG();
    }
  protected:
    void rewrite  (Module & M, std::string OldName, std::string NewNaem);
};

} // end of namespace llvm

#endif
