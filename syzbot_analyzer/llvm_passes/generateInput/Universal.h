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
#include <regex>
#include <stdio.h>
#include <vector>

using namespace llvm;
using namespace llvm::sys;
using namespace std;

#define MAX_DISTANCE 1000000
#define MAX_ANALYSIS_DEPTH 7
static llvm::DataLayout *dlForInput;

struct Input {
    llvm::Value *basePointer;
    llvm::Instruction *inst;
    llvm::Instruction *topCallsite;
    int64_t offset;
    uint64_t size;
    int distance;
    struct Input* prev;
    struct Input* next;
};

struct CalltraceItem {
    string funcName;
    string filePath;
    int line;
    bool isInline;
    int funcBound[2];
    llvm::Function *F;
    int distance;
    int numDuplication;
};

static vector<CalltraceItem*> calltrace;
static int minDistance;
static struct Input *head = NULL;
static Function *inlineCall = NULL;
static Module *TheModule = NULL;