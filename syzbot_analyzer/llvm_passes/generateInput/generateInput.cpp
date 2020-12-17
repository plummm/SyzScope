#include "InstHandler.h"

using namespace llvm;
using namespace llvm::sys;
using namespace std;

struct thisPass : public ModulePass {
    static char ID;
    thisPass() : ModulePass(ID) {}

    bool runOnModule(Module &M) override {
        struct Input *input = getInput(M);
        for (struct Input *i = input; i != NULL; i=i->next) {
            errs() << "basePointer: " << i->basePointer << " offset: " << i->offset << " distance: " << i->distance << "\n";
        }
        //typeMatchFunc(M, input);
        return true;
    }

    struct Input *getInput(Module &M) {
        locatePointerAndOffset(M);
        for (struct Input *i = input; i != NULL; i=i->next) {
            if (i->distance > minDistance) {
                struct Input *next = i->next;
                struct Input *prev = i->prev;
                if (next != NULL)
                    next->prev = prev;
                if (prev != NULL)
                    prev->next = next;
                free(i);
            }
        }
        return input;
    }

    void locatePointerAndOffset(Module &M) {
        uint64_t size = BUG_Size;
        dl = new llvm::DataLayout(&M);
        bool BUG_in_header = false;
        parseCalltrace(&M);
        minDistance = MAX_DISTANCE * calltrace.size();
        CalltraceItem *item = getFirstValidItemInCalltrace();
        if (item == NULL) {
            errs() << "calltrace is empty\n";
            return;
        }
        if (item->F == NULL) {
            errs() << "Can not find function " << item->funcName << " in one.bc\n";
            return;
        }
        auto F = item->F;
        errs() << "item->funcName: " << item->funcName << "\n";
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
                string fileName;
                // dbgloc.get() is used to check the existance of dbg info
                if (!dbgloc.get() || !dbgloc->getLine()) {
                    if (isInst<LoadInst>(&(*I)))
                        inspectInst<LoadInst, Load>(&(*I), dbgloc, NULL, 0);
                    continue;
                }
                fileName = dbgloc->getFilename().str();
                curLine = dbgloc->getLine();
                errs() << fileName << ":" << curLine << "\n";
                errs() << (*I) << "\n";
                /*if (curLine >= func_bound[0] && curLine <= func_bound[1]) {
                    if (curLine < BUG_Func_Line && basePointer != NULL)
                        break;
                }*/
                if (BUG_in_header) {
                    if (isInst<LoadInst>(&(*I)))
                        inspectInst<LoadInst, Load>(&(*I), dbgloc, NULL, 0);
                    continue;
                }
                if (isInCallTrace(fileName, curLine)) {
                    //if ((curLine == BUG_Vul_Line && stripFileName(dbgloc->getFilename().str()) == BUG_Vul_File)) {
                     //   errs() << "target site found: " << (*I) << "\n";
                        //if (isGEPInst(I))
                        //    inspectGEPInst(I);
                        if (isInst<CallInst>(&(*I)))
                            inspectInst<CallInst, Call>(&(*I), dbgloc, NULL, 0);
                        if (isInst<LoadInst>(&(*I)))
                            inspectInst<LoadInst, Load>(&(*I), dbgloc, NULL, 0);
                    //}
                }
            }
        }
        errs() << "the end\n";
        return;
    }

    CalltraceItem *getFirstValidItemInCalltrace() {
        for (auto it = calltrace.begin(); it != calltrace.end(); it++)
            if ((*it)->numDuplication == 1) {
                return *it;
            }
        return NULL;
    }

    template <class T>
    bool isInst(Instruction *I) {
        if (T *load = dyn_cast<T>(I))
            return true;
        return false;
    }

    //void inspectCallInst(llvm::Instruction *I, llvm::DebugLoc dbgloc) {
    //    dbglocMatch(dbgloc, )
    //}

    template <class InstType, class T>
    void inspectInst(llvm::Instruction *I, llvm::DebugLoc dbgloc, InstType *realSrc, int deep) {
        bool match = false;
        int index = 0;
        T::printSloganHeader(I);
        if (dbgloc->getLine() == 0) {
            PHINode *phi = nullptr;
            auto block = (*I).getParent();
            // If load inst doesn't have a valid dbg info, 
            // it means this load inst may belongs to a phi inst
            // we check out phi inst before load inst to eliminate 
            // the incorrectness of dbg info
            for (Instruction &I1 : *block) {
                if (isa<PHINode>(I1)) {
                    phi = dyn_cast<PHINode>(&(I1));
                    break;
                }
                if (&I1 == &(*I))
                    break;
            }
            if (phi != nullptr and deep < 3) {
                int n = phi->getNumIncomingValues();
                for (int i=0; i<n; i++) {
                    auto v = phi->getIncomingValue(i);
                    llvm::Instruction *incomingI = dyn_cast<Instruction>(v);
                    if (incomingI == nullptr)
                        continue;
                    // No Matryoshka doll
                    if (incomingI == I)
                        continue;
                    if (isa<Instruction>(incomingI)) {
                        auto icomDbgloc = incomingI->getDebugLoc();
                        if (!icomDbgloc)
                            continue;
                        errs() << "one of the phi incoming\n";
                        if (realSrc == NULL) {
                            realSrc = T::convertType(I);                          
                        }
                        inspectInst<InstType, T>(incomingI, icomDbgloc, realSrc, deep+1);
                        //errs() << dbgloc->getFilename().str() << ":" << dbgloc->getLine() << "\n";
                        //match = matchCalltrace(dbgloc, &index);
                        //if (index >= 0 && match)
                            //match = matchLastCaller(index, dbgloc);
                    }
                }
            }
        }
        match = matchCalltrace(dbgloc, &index);
        if (index >= 0 && match)
            match = matchLastCaller(index, dbgloc);
        if (match) {
            if (realSrc) {
                if (T::isInst(realSrc))
                    T::handleInst(realSrc);
            } else {
                if (T::isInst(I)) {
                    InstType *inst = T::convertType(I);
                    T::handleInst(inst);
                }
            }
        }
        //printDistance();
        T::printSloganTail();
    }

    void handleLoadInst(LoadInst *load) {
        llvm::Value *op = load->getPointerOperand();
        APInt ap_offset(64, 0, true);
        llvm::Value *basePointer = op->stripAndAccumulateConstantOffsets(*dl, ap_offset, true);
        int64_t offset = ap_offset.getSExtValue();
        offset -= BUG_Offset;
        struct Input *ret = (struct Input *)malloc(sizeof(struct Input));
        ret->basePointer = basePointer;
        ret->offset = offset;
        ret->size = BUG_Size;
        ret->distance = minDistance;
        ret->prev = NULL;
        ret->next = NULL;
        if (input == NULL) {
            input = ret;
        } else {
            input->prev = ret;
            ret->next = input;
            input = ret;
        }
        errs() << "-----------------------------------\n";
        errs() << "offset to base obj is " << offset << "\n";
        errs() << "-----------------------------------\n";
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

    bool matchLastCaller(int index, llvm::DebugLoc dbgloc) {
        bool match;
        string fileName = stripFileName(dbgloc->getFilename().str());
        int line = dbgloc->getLine();
        errs() << index;
        match = calltrace[index]->filePath == fileName && \
                    calltrace[index]->line == line;
        if (match) {
            match = true;
            minDistance = 0;
            errs() << "--> " << calltrace[index]->filePath << ":" << calltrace[index]->line << " True" << "\n";
        } else {
            int tmp = abs(calltrace[index]->line - line);
            match = false;
            if (tmp <= minDistance) {
                minDistance = tmp;
                match = true;
            }
            errs() << "--> " << calltrace[index]->filePath << ":" << calltrace[index]->line << " False" << "\n";
        }
        errs() << fileName << ":" << line << " " << calltrace[index]->filePath << ":" << calltrace[index]->line <<"\n";
        return match;
    }

    bool matchCalltrace(llvm::DebugLoc dbgloc, int *index) {
        bool ret = false;
        auto inlineDbg = dbgloc->getInlinedAt();
        if (inlineDbg == NULL) {
            return true;
        }
        (*index)++;
        int curLine = inlineDbg->getLine();
        string fileName = inlineDbg->getFilename().str();
        /*for (vector<CalltraceItem*>::iterator it = calltrace.begin(); it != calltrace.end(); it++) {
            if ((*it)->filePath == stripFileName(fileName) && \
                    curLine >= (*it)->funcBound[0] && curLine <= (*it)->funcBound[1]) {
                (*it)->distance = (*it)->line - curLine;
                ret = true;
            }
        }*/
        ret = matchCalltrace(inlineDbg, index);
        if (*index >= 0 && ret) {
            auto item = calltrace[*index];
            errs() << *index;
            ret = item->filePath == stripFileName(fileName) && item->line == curLine;
            if (ret) {
                errs() << "--> " << fileName << ":" << curLine << " True" << "\n";
            } else {
                errs() << "--> " << fileName << ":" << curLine << " False" << "\n";
            }
            (*index)--;
            errs() << stripFileName(fileName) << ":" << curLine << " " << item->filePath << ":" << item->line  <<"\n";
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
            vector<string> pathlist = splitBy(strlist[1], ":");
            if (pathlist.size() != 2) {
                errs() << "size of pathlist is not two: " << strlist[1] << "\n";
                continue;
            }
            item->filePath = pathlist[0];
            item->line = stoi(pathlist[1], nullptr);
            item->isInline = false;
            item->distance = MAX_DISTANCE;
            item->F = NULL;
            item->numDuplication = 0;
            item->funcBound[0] = stoi(strlist[2], nullptr);
            item->funcBound[1] = stoi(strlist[3], nullptr);
            if (strlist.size() == 5)
                item->isInline = true;
            calltrace.push_back(item);
            //errs() << "funcName:" << item->funcName << " filePath:" << item->filePath << " isInline:" << item->isInline << " line:" << item->line <<"\n";
        }
        CalltraceItem *item;
        map<string, llvm::Function*> func_contexts;
        for (int i=0; i<calltrace.size(); i++) {
            item = calltrace[i];
            string func_regx = item->funcName + "(\\.\\d+)?";
            for(auto &F : (*M)){
                if (F.isIntrinsic())
                    continue;
                if (regex_match(F.getName().str(), regex(func_regx))) {
                    func_contexts[F.getName().str()] = &F;
                    item->F = &F;
                    item->numDuplication++;
                    //break;
                }
            }
            if (item->numDuplication == 1)
                break;
        }
        for (int i=0; i < calltrace.size(); i++) {
            errs() << calltrace[i]->funcName << " has " << calltrace[i]->numDuplication <<  " duplications\n";
            if (calltrace[i]->numDuplication == 1) {
                determineCorrectContext(i, func_contexts);
                break;
            }
        }
    }

    bool dbglocMatch(llvm::DebugLoc dbgloc, string fileName, int line) {
        string dbgFileName = stripFileName(dbgloc->getFilename().str());
        int dbgLine = dbgloc->getLine();
        return fileName == dbgFileName && line == dbgLine;
    }

    void determineCorrectContext(int n, map<string, llvm::Function*> func_contexts) {
        for (int i=n; i>0; i--) {
            CalltraceItem *nextItem;
            int offset = 1;
            bool flagStop = false;
            do {
                if (i-offset < 0) {
                    flagStop = true;
                    break;
                }
                nextItem = calltrace[i-offset];
                offset++;
                if (nextItem->numDuplication > 1)
                    break;
            } while(true);
            if (flagStop)
                break;
            CalltraceItem *item = calltrace[i];
            auto F = item->F;
            inst_iterator I = inst_begin(*F), E = inst_end(*F);
            errs() << item->filePath << ":" << item->line << "\n";
            for (; I != E; ++I) {
                llvm::DebugLoc dbgloc = (*I).getDebugLoc();
                if (!dbgloc)
                    continue;
                //errs() << (*I) << "\n";
                //errs() << dbgloc->getFilename().str() << ":" << dbgloc->getLine() << "\n";
                if (isInst<CallInst>(&(*I)) && dbglocMatch(dbgloc, item->filePath, item->line)) {
                    CallInst *call = dyn_cast<CallInst>(&(*I));
                    llvm::Function *callee = call->getCalledFunction();
                    if (!callee)
                        continue;
                    errs() << "callee " << callee->getName().str() << "\n";
                    string func_regx = nextItem->funcName + "(\\.\\d+)?";
                    if (regex_match(callee->getName().str(), regex(func_regx))) {
                        errs() << nextItem->funcName << "=" << callee->getName().str() << "\n";
                        nextItem->F = func_contexts[callee->getName().str()];
                        nextItem->numDuplication = 1;
                        errs() << nextItem->funcName << "\'s context has been determined\n";
                        break;
                    }
                }
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