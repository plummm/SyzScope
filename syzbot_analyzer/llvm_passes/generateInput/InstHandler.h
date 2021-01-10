#include "Universal.h"

using namespace llvm;
using namespace llvm::sys;
using namespace std;


struct Load {
    static bool isInst(Instruction *I) {
        if (LoadInst *load = dyn_cast<LoadInst>(I))
            return true;
        return false;
    }

    static void handleInst(LoadInst *load) {
        llvm::Value *op = load->getPointerOperand();
        APInt ap_offset(64, 0, true);
        llvm::Value *basePointer = op->stripAndAccumulateConstantOffsets(*dlForInput, ap_offset, true);
        int64_t offset = ap_offset.getSExtValue();
        offset -= BUG_Offset;
        struct Input *ret = (struct Input *)malloc(sizeof(struct Input));
        errs() << "basepointer: " << (*basePointer) << "\n";
        ret->basePointer = basePointer;
        ret->inst = load;
        ret->offset = offset;
        ret->size = BUG_Size;
        ret->distance = minDistance;
        ret->prev = NULL;
        ret->next = NULL;
        if (head == NULL) {
            head = ret;
        } else {
            head->prev = ret;
            ret->next = head;
            head = ret;
        }
        errs() << "-----------------------------------\n";
        errs() << "offset to base obj is " << offset << "\n";
        errs() << "-----------------------------------\n";
    }

    static LoadInst *convertType(Instruction *I) {
        if (LoadInst *inst = dyn_cast<LoadInst>(&(*I)))
            return inst;
        return NULL;
    }

    static void printSloganHeader(Instruction *load) {
        errs() << "=============Inspect load instruction begin=============\n";
        errs() << (*load) << "\n";
        errs() << "Found a Load instruction\n";
    }

    static void printSloganTail() {
        errs() << "=============Inspect load instruction end=============\n";
    }
};

struct Call {
    static bool isInst(Instruction *I) {
        if (CallInst *call = dyn_cast<CallInst>(I))
            return true;
        return false;
    }

    static void handleInst(CallInst *call) {
        Function *callee = call->getCalledFunction();
        if (!callee)
            return;
        inst_iterator I = inst_begin(*callee), E = inst_end(*callee);
        for (; I != E; ++I) {
            if (Load::isInst(&(*I))) {
                llvm::LoadInst *load = Load::convertType(&(*I));
                Load::handleInst(load);
            }
        }
        return;
    }

    static CallInst *convertType(Instruction *I) {
        if (CallInst *inst = dyn_cast<CallInst>(&(*I)))
            return inst;
        return NULL;
    }

    static void printSloganHeader(Instruction *call) {
        errs() << "=============Inspect call instruction begin=============\n";
        errs() << (*call) << "\n";
        errs() << "Found a Call instruction\n";
    }

    static void printSloganTail() {
        errs() << "=============Inspect call instruction end=============\n";
    }
};