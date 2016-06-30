//===- RewriteHeapAllocations.cpp - Rewrite Heap Allocation Functions ----- --//
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

#define DEBUG_TYPE "rewrite-heap-allocations"

#include "safecode/Utility.h"
#include "safecode/RewriteHeapAllocations.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/LLVMContext.h"
#include <vector>

namespace llvm {

// Identifier variable for the pass
char RewriteHeapAllocations::ID = 0;


// Register the pass
static RegisterPass<RewriteHeapAllocations> P ("heap-allocations-rewriter",
                                               "Heap Allocations Rewrite Transform");


//
// Function: rewrite
//
// Description:
//  rename function from OldName to New Name in a module
//
// Inputs:
//  M - Module M
//  OldName - Old Name
//  NewName - New Name
//
// Return value:
//  void
//
void
RewriteHeapAllocations::rewrite (Module & M, std::string OldName, std::string NewName) {
  Function * F = M.getFunction(OldName);
  if(!F) return;

  Constant * New = M.getOrInsertFunction (NewName, F->getFunctionType());
  Function * newFunc = M.getFunction(NewName);
  assert(newFunc && "Failed to insert the new function");
  F->replaceAllUsesWith(newFunc);
  F->eraseFromParent();
}

bool
RewriteHeapAllocations::runOnModule (Module & M) {
  rewrite (M, "malloc", "__sc_bb_malloc");
  rewrite (M, "calloc", "__sc_bb_calloc");
  rewrite (M, "realloc","__sc_bb_realloc");
  rewrite (M, "strdup", "__sc_bb_strdup");
  rewrite (M, "getenv", "__sc_bb_getenv");

  return true;
}

} // end of namespace llvm
