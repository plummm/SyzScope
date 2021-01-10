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
static cl::opt<string> BUG_Vul_File ("VulFile", cl::desc("The file that UAF/OOB occurs"), cl::init(""));
static cl::opt<string> BUG_Func_File ("FuncFile", cl::desc("The bug may occur in an inline function, this argument indicate the file of first non-inline caller"), cl::init(""));
static cl::opt<string> BUG_Func ("Func", cl::desc("The function that UAF/OOB occurs"), cl::init(""));
static cl::opt<string> Calltrace_File ("CalltraceFile", cl::desc("The path of a calltrace"), cl::init(""));
static cl::opt<int> BUG_Vul_Line ("VulLine", cl::desc("Which line of the vulerable function that UAF/OOB occur"), cl::init(0));
static cl::opt<int> BUG_Func_Line ("FuncLine", cl::desc("Which line of the caller that UAF/OOB occur"), cl::init(0));
static cl::opt<int> BUG_Offset ("Offset", cl::desc("Offset from base pointer that trigger OOB/UAF"), cl::init(0));
static cl::opt<int> BUG_Size ("Size", cl::desc("Size of vulnerable object"), cl::init(0));
static llvm::DataLayout *dlForInput;

struct Input {
    llvm::Value *basePointer;
    llvm::Instruction *inst;
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