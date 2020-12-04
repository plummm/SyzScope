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

#define MAX_DISTANCE 1000000

using namespace llvm;
using namespace llvm::sys;
using namespace std;

static cl::opt<string> BUG_Vul_File ("VulFile", cl::desc("The file that UAF/OOB occurs"), cl::init(""));
static cl::opt<string> BUG_Func_File ("FuncFile", cl::desc("The bug may occur in an inline function, this argument indicate the file of first non-inline caller"), cl::init(""));
static cl::opt<string> BUG_Func ("Func", cl::desc("The function that UAF/OOB occurs"), cl::init(""));
static cl::opt<string> Calltrace_File ("CalltraceFile", cl::desc("The path of a calltrace"), cl::init(""));
static cl::opt<int> BUG_Vul_Line ("VulLine", cl::desc("Which line of the vulerable function that UAF/OOB occur"), cl::init(0));
static cl::opt<int> BUG_Func_Line ("FuncLine", cl::desc("Which line of the caller that UAF/OOB occur"), cl::init(0));
static cl::opt<int> BUG_Offset ("Offset", cl::desc("Offset from base pointer that trigger OOB/UAF"), cl::init(0));
static cl::opt<int> BUG_Size ("Size", cl::desc("Size of vulnerable object"), cl::init(0));

struct Input {
    llvm::Value *basePointer;
    int64_t offset;
    uint64_t size;
};

struct CalltraceItem {
    string funcName;
    string filePath;
    int line;
    bool isInline;
    int funcBound[2];
    llvm::Function *F;
    int distance;
};

static vector<CalltraceItem*> calltrace;
static int minDistance;
struct thisPass : public ModulePass {
    static char ID;
    llvm::DataLayout *dl;
    thisPass() : ModulePass(ID) {}

    bool runOnModule(Module &M) override {
        struct Input *input = locatePointerAndOffset(M);
        //typeMatchFunc(M, input);
        return true;
    }

    struct Input *locatePointerAndOffset(Module &M) {
        llvm::Value *basePointer = NULL;
        int64_t offset = 0;
        uint64_t size = BUG_Size;
        dl = new llvm::DataLayout(&M);
        bool BUG_in_header = false;
        parseCalltrace(&M);
        minDistance = MAX_DISTANCE * calltrace.size();
        CalltraceItem *item = calltrace.back();
        auto F = item->F;
        if (item->funcName == BUG_Func) {
            errs() << "Found target function: " << item->F->getName().str() << "\n";
            if (item->funcBound[0] > BUG_Func_Line)
                BUG_in_header = true;
            inst_iterator I = inst_begin(*F), E = inst_end(*F);
            for (; I != E; ++I) {
                llvm::DebugLoc dbgloc = (*I).getDebugLoc();
                if (!BUG_in_header && !dbgloc) {
                    //errs() << (*I) << "\n";
                    continue;
                }
                int curLine = 0;
                try {
                    curLine = dbgloc->getLine();
                    if (!curLine) {
                        //errs() << "90 "<< (*I) << "\n";
                        if (isLoadInst(I))
                            inspectLoadInst(I, basePointer, &offset);
                        continue;
                }
                } catch(...) {
                    //errs() << "96 " << (*I) << "\n";
                    if (isLoadInst(I))
                            inspectLoadInst(I, basePointer, &offset);
                    continue;
                }
                errs() << dbgloc->getFilename().str() << ":" << curLine << "\n";
                //errs() << (*I) << "\n";
                /*if (curLine >= func_bound[0] && curLine <= func_bound[1]) {
                    if (curLine < BUG_Func_Line && basePointer != NULL)
                        break;
                }*/
                if (BUG_in_header) {
                    if (isLoadInst(I))
                        inspectLoadInst(I, basePointer, &offset);
                    continue;
                }
                if (isInCallTrace(dbgloc->getFilename().str(), curLine)) {
                    //if ((curLine == BUG_Vul_Line && stripFileName(dbgloc->getFilename().str()) == BUG_Vul_File)) {
                     //   errs() << "target site found: " << (*I) << "\n";
                        //if (isGEPInst(I))
                        //    inspectGEPInst(I);
                        if (isLoadInst(I))
                            inspectLoadInst(I, basePointer, &offset);
                    //}
                }
            }
        }
        struct Input *ret = (struct Input *)malloc(sizeof(struct Input));
        ret->basePointer = basePointer;
        ret->offset = offset;
        ret->size = size;
        return ret;
    }

    bool isLoadInst(inst_iterator I) {
        if (LoadInst *load = dyn_cast<LoadInst>(&(*I)))
            return true;
        return false;
    }

    bool isGEPInst(inst_iterator I) {
        if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(&(*I)))
            return true;
        return false;
    }

    void inspectLoadInst(inst_iterator I, llvm::Value *basePointer, int64_t *offset) {
        if(LoadInst *load = dyn_cast<LoadInst>(&(*I))) {
            errs() << (*I) << "\n";
            errs() << "Found a Load instruction\n"; 
            int curDistance = accumulateDistance();
            if (minDistance > curDistance) {
                minDistance = curDistance;
                llvm::Value *op = load->getPointerOperand();
                APInt ap_offset(64, 0, true);
                basePointer = op->stripAndAccumulateConstantOffsets(*dl, ap_offset, true);
                *offset = ap_offset.getSExtValue();
                //errs() << "offset to base obj is " << offset << "\n";
                *offset -= BUG_Offset;
                errs() << "offset to base obj is " << *offset << "\n";
            }
            errs() << "Current min distance: " << minDistance << "\n";
            printDistance();
        }
    }

    void inspectGEPInst(inst_iterator I) {
        if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(&(*I))) {
            errs() << (*I) << "\n";
            errs() << "Found a GEP instruction" << gep << "\n";
        }
    }

    int accumulateDistance() {
        int ret = 0;
        for (vector<CalltraceItem*>::iterator it = calltrace.begin(); it != calltrace.end(); it++) {
            if ((*it)->distance > 0)
                ret += (*it)->distance;
            else
                ret -= (*it)->distance;
        }
        return ret;
    }

    void printDistance() {
        for (vector<CalltraceItem*>::iterator it = calltrace.begin(); it != calltrace.end(); it++) {
            errs() << "filePath:" << (*it)->filePath << " funcName:" << (*it)->funcName << " line:" << (*it)->line << " distance:" << (*it)->distance << " bounds:" << (*it)->funcBound[0] << "-" << (*it)->funcBound[1] << "\n";
        }
    }

    bool isInCallTrace(string fileName, int curLine) {
        bool ret = false;
        string sFileName = stripFileName(fileName);
        for (vector<CalltraceItem*>::iterator it = calltrace.begin(); it != calltrace.end(); it++) {
            //errs() << "filePath: " << (*it)->filePath << " fileName: " << sFileName << "\n";
            if ((*it)->filePath == sFileName) {
                if (curLine >= (*it)->funcBound[0] && curLine <= (*it)->funcBound[1]) {
                    (*it)->distance = (*it)->line - curLine;
                    ret = true;
                }
            }
        }
        return ret;
    }

    void parseCalltrace(Module *M) {
        string line;
        vector<string> strlist;
        ifstream fin;
        fin.open(Calltrace_File);
        while (getline(fin, line)) {
            //errs() << line << "\n";
            strlist = splitBy(line, " ");
            if (strlist.size() < 4) {
                errs() << "size of strlist is less than 4: " << line << "\n";
                continue;
            }
            CalltraceItem *item = new CalltraceItem;
            item->funcName = strlist[0];
            item->funcBound[0] = stoi(strlist[2], nullptr);
            item->funcBound[1] = stoi(strlist[3], nullptr);
            vector<string> pathlist = splitBy(strlist[1], ":");
            if (pathlist.size() != 2) {
                errs() << "size of pathlist is not two: " << strlist[1] << "\n";
                continue;
            }
            item->filePath = pathlist[0];
            item->line = stoi(pathlist[1], nullptr);
            item->isInline = false;
            item->distance = MAX_DISTANCE;
            if (strlist.size() == 5)
                item->isInline = true;
            calltrace.push_back(item);
            //errs() << "funcName:" << item->funcName << " filePath:" << item->filePath << " isInline:" << item->isInline << " line:" << item->line <<"\n";
            if (item->funcName == BUG_Func)
                break;
        }
        CalltraceItem *item = calltrace.back();
        for(auto &F : (*M)){
            if (F.getName().str() == item->funcName) {
                item->F = &F;
                break;
            }
        }
    }

    vector<string> splitBy(string s, string delimiter) {
        vector<string> ret;
        size_t pos = 0;
        while ((pos = s.find(delimiter)) != std::string::npos) {
            ret.push_back(s.substr(0, pos));
            s.erase(0, pos + delimiter.length());
        }
        ret.push_back(s);
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