//===- InlineBBRuntimeFunctions.h - Inline BBAC RuntimeFunctions----------- --//
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

#ifndef _INLINE_BB_RUNTIME_FUNCTIONS_H_
#define _INLINE_BB_RUNTIME_FUNCTIONS_H_

#include "llvm/Pass.h"
#include "safecode/DebugInstrumentation.h"

namespace llvm {

class InlineBBRuntimeFunctions : public ModulePass {
 public:
  static char ID;
  InlineBBRuntimeFunctions () : ModulePass(ID) {}
  virtual bool runOnModule (Module &M);
  const char *getPassName() const {
    return "Inline baggy bounds accurate checks runtime functions";
  }

  virtual void getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addRequired<DebugInstrument>();
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
