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

static cl::opt<string> BUG_Vul_File ("VulFile", cl::desc("The file that UAF/OOB occurs"), cl::init(""));
static cl::opt<string> BUG_Func_File ("FuncFile", cl::desc("The bug may occur in an inline function, this argument indicate the file of first non-inline caller"), cl::init(""));
static cl::opt<string> BUG_Func ("Func", cl::desc("The function that UAF/OOB occurs"), cl::init(""));
static cl::opt<int> BUG_Vul_Line ("VulLine", cl::desc("Which line of the vulerable function that UAF/OOB occur"), cl::init(0));
static cl::opt<int> BUG_Func_Line ("FuncLine", cl::desc("Which line of the caller that UAF/OOB occur"), cl::init(0));
static cl::opt<int> BUG_Offset ("Offset", cl::desc("Offset from base pointer that trigger OOB/UAF"), cl::init(0));

struct Input {
    llvm::Value *basePointer;
    int offset;
};
struct thisPass : public ModulePass {
    static char ID;
    llvm::DataLayout *dl;
    thisPass() : ModulePass(ID) {}

    bool runOnModule(Module &M) override {
        struct Input *input = locatePointerAndOffset(M);
        typeMatchFunc(M, input);
        return true;
    }

    struct Input *locatePointerAndOffset(Module &M) {
        llvm::Value *basePointer = NULL;
        uint64_t offset = -1;
        int func_bound[2];
        dl = new llvm::DataLayout(&M);
        for(auto &F : M){
            if (F.getName().str() == BUG_Func) {
                getFuncBoundary(&F, func_bound);
                for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
                    auto dbgloc = (*I).getDebugLoc();
                    if (dbgloc && dbgloc->getLine()) {
                        int curLine = dbgloc->getLine();
                        if (curLine >= func_bound[0] && curLine <= func_bound[1]) {
                            //errs() << dbgloc->getFilename().str() << ":" << curLine << "\n";
                            if (curLine > BUG_Func_Line && basePointer != NULL)
                                break;
                        }
                        if (curLine == BUG_Vul_Line && stripFileName(dbgloc->getFilename().str()) == BUG_Vul_File) {
                            auto a = (*I).getOperand(0);
                            auto type = a->getType();
                            if(LoadInst *load = dyn_cast<LoadInst>(&(*I))) {
                                errs() << (*I) << "\n";
                                errs() << "This is a Load instruction\n"; 
                                llvm::Value *op = load->getPointerOperand();
                                APInt ap_offset(64, 0, true);
                                basePointer = op->stripAndAccumulateConstantOffsets(*dl, ap_offset, true);
                                offset = ap_offset.getSExtValue();
                                errs() << "offset to base obj is " << offset << "\n";
                                if (offset >= BUG_Offset)
                                    offset -= BUG_Offset;
                                else
                                    offset = 0;
                                errs() << "offset to base obj is " << offset << "\n";
                            }
                        }
                    }
                }
                break;
            }
        }
        struct Input *ret = (struct Input *)malloc(sizeof(struct Input));
        ret->basePointer = basePointer;
        ret->offset = offset;
        return ret;
    }

    void typeMatchFunc(Module &M, struct Input *input) {
        llvm::StringRef basePointerStructName;
        input->basePointer->print(errs());
        llvm::Type *type = input->basePointer->getType();
        llvm::Type *pointToType = type->getPointerElementType();
        llvm::Value *op;
        //errs() << "t1 " << type->getTypeID() << " t2 " << type->getPointerElementType()->getTypeID() << "\n";
        if (pointToType->isStructTy()){
            errs() << "\nname: " << pointToType->getStructName() << "\n";
            basePointerStructName = pointToType->getStructName();
        }

        for(auto &F : M){
            for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
                if(LoadInst *load = dyn_cast<LoadInst>(&(*I))) {
                    op = load->getPointerOperand();
                } else if(StoreInst *store = dyn_cast<StoreInst>(&(*I))) {
                    op = store->getPointerOperand();
                } /*else if(CallInst *call = dyn_cast<CallInst>(&(*I))) {
                    if (call->isIndirectCall()) {
                        //
                    }
                }*/ else 
                    continue;
                APInt ap_offset(64, 0, true);
                auto basePointer = op->stripAndAccumulateConstantOffsets(*dl, ap_offset, true);
                auto offset = ap_offset.getSExtValue();
                
                llvm::Type *t = basePointer->getType();
                if (t->isPointerTy())
                    t = t->getPointerElementType();
                if (t->isStructTy()) {
                    if (t->getStructName() == basePointerStructName && offset>=input->offset) {
                        errs() << "find additonal use with offset " << offset << "\n";
                        errs() << (*I) << "\n";
                        auto dbg = I->getDebugLoc();
                        errs() << dbg->getFilename() << ":" << dbg->getLine() << "\n";
                        break;
                    }
                }
            }
        }
    }

    int* getFuncBoundary(llvm::Function *F, int ret[2]) {
        ret[0] = 0;
        ret[1] = 0;
        for (inst_iterator I = inst_begin(*F), E = inst_end(*F); I != E; ++I) {
            auto dbgloc = (*I).getDebugLoc();
            if (dbgloc && dbgloc->getLine() && stripFileName(dbgloc->getFilename().str()) == BUG_Func_File) {
                ret[1] = dbgloc->getLine();
                if (ret[0] == 0)
                    ret[0] = ret[1];
            }
        }
        return ret;
    }

    string stripFileName(string fileName) {
        if (fileName.find("./") == 0) {
            return fileName.substr(2, fileName.size());
        }
        return fileName;
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