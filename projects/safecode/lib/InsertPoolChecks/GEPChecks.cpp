//===- GEPChecks.cpp - Insert GEP run-time checks ------------------------- --//
// 
//                     The LLVM Compiler Infrastructure
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
// 
//===----------------------------------------------------------------------===//
//
// This pass instruments GEPs with run-time checks to ensure safe array and
// structure indexing.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "safecode"

#include "llvm/ADT/Statistic.h"
#include "llvm/Support/CommandLine.h"
#include "safecode/GEPChecks.h"
#include "safecode/Utility.h"

namespace llvm {

char InsertGEPChecks::ID = 0;

static RegisterPass<InsertGEPChecks>
X ("gepchecks", "Insert GEP run-time checks");

//
// Command Line Options
//

// Disable checks on pure structure indexing
cl::opt<bool> DisableStructChecks ("disable-structgepchecks", cl::Hidden,
                                   cl::init(false),
                                   cl::desc("Disable Struct GEP Checks"));

// Pass Statistics
namespace {
  STATISTIC (GEPChecks, "Bounds Checks Added");
  STATISTIC (SafeGEP,   "GEPs proven safe by SAFECode");
}

//
// Method: visitGetElementPtrInst()
//
// Description:
//  This method checks to see if the specified GEP is safe.  If it cannot prove
//  it safe, it then adds a run-time check for it.
//
void
InsertGEPChecks::visitGetElementPtrInst (GetElementPtrInst & GEP) {
  //
  // Don't insert a check if GEP only indexes into a structure and the
  // user doesn't want to do structure index checking.
  //
  if (DisableStructChecks && indexesStructsOnly (&GEP)) {
    return;
  }

  //
  // Get the function in which the GEP instruction lives.
  //
  Value * PH = ConstantPointerNull::get (getVoidPtrType(GEP.getContext()));
  BasicBlock::iterator InsertPt = &GEP;
  ++InsertPt;

  //
  // Because we only need to pass the source pointers and the result pointers to boundscheckui. We
  // introduce two vectors, the SrcPtrs and the ResultPtrs, to store the source pointers and result
  // pointers of a single getelementptr instruction.
  //
  std::vector<Value *> SrcPtrs;
  std::vector<Value *> ResultPtrs;

  //
  // The getelementptr returns a vector of pointers, instead of a single address, when one or more
  // of its arguments is a vector:
  //
  //   <result> = getelementptr <ty>, <ptr vector> <ptrval>, <vector index type> <idx>
  //
  // There are three cases of vectorized getelementptr:
  //
  // ; All arguments are vectors:
  // ;   A[i] = ptrs[i] + offsets[i]*sizeof(i8)
  // %A = getelementptr i8, <4 x i8*> %ptrs, <4 x i64> %offsets
  //
  // ; Add the same scalar offset to each pointer of a vector:
  // ;   A[i] = ptrs[i] + offset*sizeof(i8)
  // %A = getelementptr i8, <4 x i8*> %ptrs, i64 %offset
  //
  // ; Add distinct offsets to the same pointer:
  //;   A[i] = ptr + offsets[i]*sizeof(i8)
  // %A = getelementptr i8, i8* %ptr, <4 x i64> %offsets
  //
  // ; In all cases described above the type of the result is <4 x i8*>
  //
  // All vector arguments should have the same number of elements. Thus we can know that
  //
  // 1. When the type of a getelementptr instruction is vector, then it is a vectorized getelementptr.
  // 2. If a getelementptr instruction is a vectorized getelementptr, then there are three possible
  //    cases: a. the ptr is a vector, the offset is not a vector. b. the offset is a vector, the ptr
  //    is not a vector. c. the ptr and offset are both vectors.
  // 3. If any of ptr or offset is a vector, the length of that vector should be equal to the length of
  //    the result vector.
  //
  if (GEP.getType()->isVectorTy()) {
    size_t ResultLength = GEP.getType()->getVectorNumElements();

    //
    // Insert every result pointer to ResultPtrs.
    //
    for (size_t r_i = 0; r_i < ResultLength; r_i ++) {
      Value * I = ConstantInt::get (Type::getInt64Ty(GEP.getContext()), r_i, false);
      Value * EEI = ExtractElementInst::Create(&GEP,
                                               I,
                                               GEP.getName() + ".extracted",
                                               InsertPt);
      ResultPtrs.push_back(EEI);
    }

    Value * PointerOperand = GEP.getPointerOperand();

    //
    // For the case that source pointer is a vector, extract all the elements of that vector and insert the
    // the elements to SrcPtrs. The final size of ScrPtrs is equal to the length of getelementptr vector.
    //
    if (PointerOperand ->getType() -> isVectorTy()) {
      size_t POLength = PointerOperand -> getType() -> getVectorNumElements();
      assert (POLength == ResultLength && "All vector arguments should have same number of elements");
      for (size_t po_i = 0; po_i < POLength ; ++po_i) {
        Value * I = ConstantInt::get (Type::getInt64Ty(GEP.getContext()), po_i, false);
        Value * POElement = ExtractElementInst::Create(PointerOperand,
                                                       I,
                                                       PointerOperand->getName() + ".extracted",
                                                       InsertPt);
        SrcPtrs.push_back(POElement);
      }
    }
    //
    // For the case that source pointer is a scalar, insert one piece of that scalar to the ScrPtrs.
    // The final size of ScrPtrs is 1.
    //
    else {
      Value * SrcPtr = castTo (GEP.getPointerOperand(),
                               getVoidPtrType(GEP.getContext()),
                               GEP.getName()+".cast",
                               InsertPt);
      for (size_t sr_i = 0 ; sr_i < ResultLength; ++sr_i)
        SrcPtrs.push_back(SrcPtr);
    }
  }

  //
  // Scalar getelementptr, the result is a scalar, and neither ptr nor offset is a vector.
  //
  else {
    //
    // Make this an actual cast instruction; it will make it easier to update
    // DSA.
    //
    Value * SrcPtr = castTo (GEP.getPointerOperand(),
                             getVoidPtrType(GEP.getContext()),
                             GEP.getName()+".cast",
                             InsertPt);

    Instruction * ResultPtr = castTo (&GEP,
                                      getVoidPtrType(GEP.getContext()),
                                      GEP.getName() + ".cast",
                                      InsertPt);

    SrcPtrs.push_back(SrcPtr);
    ResultPtrs.push_back(ResultPtr);
  }

  // For each of the result pointer, insert a boundscheckui call.
  for (size_t i = 0; i < ResultPtrs.size(); ++i) {

    //
    // Create the call to the run-time check.
    //
    std::vector<Value *> args(1, PH);

    //
    // If the size of SrcPtrs is 1, then the source pointer is a scalar. This scalar will be shared
    // with all the result pointers.
    //
    if(SrcPtrs.size() == 1) {
      args.push_back (SrcPtrs[0]);
    }
    //
    // If the size of SrcPtrs is not 1, then each result pointers must have its own source pointer.
    //
    else {
      args.push_back (SrcPtrs[i]);
    }
    args.push_back (ResultPtrs[i]);
    CallInst * CI = CallInst::Create (PoolCheckArrayUI, args, "", InsertPt);

    //
    // Add debugging info metadata to the run-time check.
    //
    if (MDNode * MD = GEP.getMetadata ("dbg"))
      CI->setMetadata ("dbg", MD);

    //
    // Update the statistics.
    //
    ++GEPChecks;
  }
  return;
}

//
// Method: doInitialization()
//
// Description:
//  Perform module-level initialization before the pass is run.  For this
//  pass, we need to create a function prototype for the GEP check function.
//
// Inputs:
//  M - A reference to the LLVM module to modify.
//
// Return value:
//  true - This LLVM module has been modified.
//
bool
InsertGEPChecks::doInitialization (Module & M) {
  //
  // Create a function prototype for the function that performs incomplete
  // pointer arithmetic (GEP) checks.
  //
  Type * VoidPtrTy = getVoidPtrType (M.getContext());
  Constant * F = M.getOrInsertFunction ("boundscheckui",
                                        VoidPtrTy,
                                        VoidPtrTy,
                                        VoidPtrTy,
                                        VoidPtrTy,
                                        NULL);

  //
  // Mark the function as readonly; that will enable it to be hoisted out of
  // loops by the standard loop optimization passes.
  //
  (cast<Function>(F))->addFnAttr (Attribute::ReadOnly);
  // Insert boundscheckui to llvm.compiler.used to make it survive from compiler
  // optimization.
  registerLLVMCompilerUsed (M, F);
  return true;
}

bool
InsertGEPChecks::runOnFunction (Function & F) {
  //
  // Get pointers to required analysis passes.
  //
  TD      = &F.getParent()->getDataLayout();
  abcPass = &getAnalysis<ArrayBoundsCheckLocal>();

  //
  // Get a pointer to the run-time check function.
  //
  PoolCheckArrayUI = F.getParent()->getFunction ("boundscheckui");

  //
  // Visit all of the instructions in the function.
  //
  visit (F);
  return true;
}

bool
InsertGEPChecks::doFinalization (Module & M) {
  // unregister the PoolCheckArrayUI from llvm.compiler.used
  unregisterLLVMCompilerUsed (M, PoolCheckArrayUI);
  return true;
}

}

