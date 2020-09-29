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
        dl = new llvm::DataLayout(&M);
        for(auto &F : M){
            if (F.getName().str() == "tcp_fastretrans_alert") {
                int lastLine = 0;
                for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
                    auto dbgloc = (*I).getDebugLoc();
                    if (dbgloc && dbgloc->getLine()) {
                        //errs() << dbgloc->getFilename().str() << ":" << dbgloc->getLine() << "\n";
                        //lastLine = dbgloc->getLine();
                        if (dbgloc->getLine() == 1846 && dbgloc->getFilename().str() == "./include/net/tcp.h") {
                            auto a = (*I).getOperand(0);
                            auto type = a->getType();
                            if(GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(&(*I))) {
                                // processing on GEP
                                errs() << (*I) << "\n";
                                errs() << "This is a GEP instruction\n"; 
                                uint64_t offset = getOffsetOfBaseObj(&(*I));
                                errs() << "offset to base obj is " << offset << "\n";
                            }
                        }
                    }
                }
            }
        }
        return true;
    }

    uint64_t getOffsetOfBaseObj(llvm::Instruction *I) {
        uint64_t ret = 0;
        GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(&(*I));
        APInt ap_offset(64, 0, true);
        bool success = GEP->accumulateConstantOffset(*dl, ap_offset);
        assert(success);
        ret = ap_offset.getSExtValue();
        return ret;
    }

    uint64_t getSizeOfObj(llvm::Value *op) {
        uint64_t targetObjSize = 0;
        llvm::Type *t = op->getType();
        if (t->isPointerTy()) {
            llvm::Type *targetObjType = t->getPointerElementType();
            targetObjSize = dl->getTypeAllocSize(targetObjType);
        }

        return targetObjSize;
    }
};

char thisPass::ID = 0;
static RegisterPass<thisPass> X("generateInput", "Generate input for static analysis");