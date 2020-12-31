#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/InstIterator.h"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <vector>

using namespace llvm;
using namespace llvm::sys;
using namespace std;

struct thisPass : public ModulePass {
    static char ID;
    llvm::DataLayout *dl;
    thisPass() : ModulePass(ID) {}

    bool runOnModule(Module &M) override {
        struct Input *input = locatePointerAndOffset(M);
        return true;
    }
}