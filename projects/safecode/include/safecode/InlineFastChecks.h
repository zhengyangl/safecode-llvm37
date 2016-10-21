//===- InlineFastChecks.h - Inline Fast Checks ---------------------------- --//
// 
//                          The SAFECode Compiler 
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
// 
//===----------------------------------------------------------------------===//
//
// This pass replaces calls to fastlscheck within inline code to perform the
// check.  It is designed to provide the advantage of libLTO without libLTO.
//
//===----------------------------------------------------------------------===//
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Utils/Cloning.h"


namespace llvm {
  //
  // Pass: InlineFastChecks
  //
  // Description:
  //  This pass inlines fast checks to make them faster.
  //
  struct InlineFastChecks : public ModulePass {
   public:
    static char ID;
    InlineFastChecks() : ModulePass(ID) {}
     virtual bool runOnModule (Module & M);
     const char *getPassName() const {
       return "Inline fast checks transform";
     }
    
     virtual void getAnalysisUsage(AnalysisUsage &AU) const {
       return;
     }

   private:
     // Private methods
     bool inlineCheck (Function * F);
     bool createBodyFor (Function * F);
     bool createDebugBodyFor (Function * F);
     Value * castToInt (Value * Pointer, BasicBlock * BB);
     Value * addComparisons (BasicBlock *, Value *, Value *, Value *);
  };
}
