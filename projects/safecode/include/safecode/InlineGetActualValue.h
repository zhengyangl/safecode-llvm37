//===- InlineGetActualValue.h - Inline pchk_getActualValue function ------- --//
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


#ifndef _INLINE_GET_ACTUAL_VALUE_H_
#define _INLINE_GET_ACTUAL_VALUE_H_

#include "llvm/Pass.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "safecode/RewriteOOB.h"

namespace llvm {

class InlineGetActualValue : public ModulePass {
 public:
  static char ID;
  InlineGetActualValue () : ModulePass(ID) {}
  virtual bool runOnModule (Module &M);
  const char *getPassName() const {
    return "Inline pchk_getActualValue() function calls";
  }

  virtual void getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addRequired<RewriteOOB>();
    AU.addRequired<AssumptionCacheTracker>();
    AU.addRequired<CallGraphWrapperPass>();
    AU.addRequired<AliasAnalysis>();
    return;
  }
 private:
  bool createGetActualValueBodyFor (Function *F);
  bool inlineCheck (Function * F);
};
} // end namespace llvm;


#endif
