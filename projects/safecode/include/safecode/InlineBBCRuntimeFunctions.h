//===- InlineBBCRuntimeFunctions.h - Inline BBC RuntimeFunctions----------- --//
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

#ifndef _INLINE_BBC_RUNTIME_FUNCTIONS_H_
#define _INLINE_BBC_RUNTIME_FUNCTIONS_H_

#include "llvm/Pass.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "safecode/DebugInstrumentation.h"

namespace llvm {

template<bool isRewriteOOBDisabled>
class InlineBBCRuntimeFunctions : public ModulePass {
 public:
  static char ID;
  InlineBBCRuntimeFunctions () : ModulePass(ID) {}
  virtual bool runOnModule (Module &M);
  const char *getPassName() const {
    if (isRewriteOOBDisabled)
      return "Inline baggy bounds checks(BBC) runtime functions with oob rewritting disabled";
    else
      return "Inline baggy bounds checks(BBC) runtime functions with oob rewritting enabled";
  }

  virtual void getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addRequired<DebugInstrument>();
    AU.addRequired<AssumptionCacheTracker>();
    AU.addRequired<CallGraphWrapperPass>();
    AU.addRequired<AliasAnalysis>();
    return;
  }
 private:
  bool createPoolCheckUIBodyFor (Function * F);
  bool createBoundsCheckUIBodyFor (Function * F);
  bool createPoolRegisterBodyFor (Function * F);
  bool createPoolUnregisterBodyFor (Function * F);
  bool createGlobalDeclarations (Module & M);
  bool inlineCheck (Function * F);
};
} // end namespace llvm;

#endif
