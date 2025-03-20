#include "BPatch.h"
#include "BPatch_addressSpace.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "BPatch_point.h"
#include <stdio.h>
#include <string.h>
#include "Instruction.h"
#include "Operand.h"
#define BUFLEN 520
#define OUTCHANNEL stdout
using namespace std;
using namespace Dyninst;
using namespace InstructionAPI;

BPatch bpatch;
vector<string> compiler_build_in = {"_start",
    "main",//后加
    " __libc_start_main",
    "__libc_init_first",
    "__libc_csu_init",
    "__libc_csu_fini",
    "_init",
    "__x86.get_pc_thunk.ax",
    "__x86.get_pc_thunk.bx",
    "__x86.get_pc_thunk.cx",
    "__x86.get_pc_thunk.dx",
    "__gmon_start__ ",
    "frame_dummy",
    "__do_global_dtors_aux",
    "__do_global_ctors_aux",
    "register_tm_clones",
    "deregister_tm_clones",
    "_exit",
    "__call_tls_dtors",
    "_fini",
    "__stat",
    "__fstat",
    "__plt_dispatcher",
    "__divsc3",
    "__mulsc3",
    "stat64",
    "fstat64",
    "lstat64",
    "fstatat64",
    "atexit",
    "_dl_relocate_static_pie",
    "__divsc3",
    "__mulsc3"};
/**
 * @brief 
 * 
 * @param candidate_name 
 * @return true 
 * @return false 
 */
    bool is_compiler_build_in(string candidate_name);
/**
 * @brief 
 * 
 * @param appImage 
 * @param name 
 * @param loc 
 * @return vector<BPatch_point *>* 
 */
vector<BPatch_point *> *find_point_of_func(BPatch_image *appImage,const char *name,BPatch_procedureLocation loc);

/**
 * @brief 判断数组是否已满，若满则将数组内容写入文件
 * 
 * @param appImage 
 * @return BPatch_snippet* 
 */
BPatch_snippet *arrayFullSaveInFile(BPatch_image *appImage);

/**
 * @brief Create a And Insert Fopen object
 * 
 * @param app 目标程序的镜像
 * @param path_name 文件地址
 * @return true 
 * @return false 
 */
bool createAndInsertFopen(BPatch_addressSpace *app, char *path_name);

/**
 * @brief 
 * 
 * @param app 二进制文件
 * @return true 
 * @return false 
 */
bool createAndInsertInitialization(BPatch_addressSpace *app);

/**
 * @brief 过滤共享库、动态库的所有函数
 * 
 * @param appImage 二进制文件的映像
 * @param funcs 存储过滤后的函数集合
 */
void findFunctionEntries(BPatch_image *appImage,vector<BPatch_function *> *funcs);


/**
 * @brief 遍历所有函数的基本块，并获得每一个基本块的最后一条指令在Image的插桩点
 * 
 * @param appImage 二进制文件的映像
 * @param basicAddress 存储二进制文件镜像的插桩点
 * @return true 
 * @return false 
 */
bool get_points(BPatch_image *appImage, vector<BPatch_point *> *basicAddress);


/**
 * @brief 对传递的参数basicAddress中所有的插桩点进行插桩
 * 
 * @param app 二进制文件
 * @param basicAddress 二进制文件镜像的插桩点
 * @return true 
 * @return false 
 */
bool createAndInsertBasic(BPatch_addressSpace *app,vector<BPatch_point *> &basicAddress);