#include"DyninstBasic.h"

bool is_compiler_build_in(string candidate_name) {
    for (auto it = compiler_build_in.begin(); it != compiler_build_in.end();it++) {
      if (candidate_name == *it)
        return true;
    }
  
    return false;
  }

vector<BPatch_point *> *find_point_of_func(BPatch_image *appImage,const char *name,BPatch_procedureLocation loc) {
    vector<BPatch_function *> functions;
    vector<BPatch_point *> *points;
  
    //从 appImage 查找名称为 name 的所有函数
    appImage->findFunction(name, functions);
  
    if (functions.size() == 0) {
      fprintf(OUTCHANNEL, "No function %s\n", name);
      return points;
    }
  
    //查找 functions[0] 处的 loc 位置的 BPatch_point：
    points = functions[0]->findPoint(loc);
  
    if (points == NULL) {
      fprintf(OUTCHANNEL, "No wanted point for function %s\n", name);
    }
  
    return points;
  }

BPatch_snippet *arrayFullSaveInFile(BPatch_image *appImage) {
    //获取变量
    BPatch_variableExpr *beginPtr = appImage->findVariable("beginPtr");
    BPatch_variableExpr *endPtr = appImage->findVariable("endPtr");
    BPatch_variableExpr *currentPtr = appImage->findVariable("currentPtr");
    //查找 fwrite 函数
    BPatch_snippet *fwriteCall;
    cout<<"fwriteCall"<<endl;
    vector<BPatch_function *> fwriteFuncs;
    appImage->findFunction("fwrite", fwriteFuncs);
  
    if (fwriteFuncs.size() == 0) {
      fprintf(OUTCHANNEL, "error:Could not find <fwrite>\n");
      fwriteCall = NULL;
    } else {
      // fwrite(beginPtr, 1, currentPtr-beginPtr, outFile);
      vector<BPatch_snippet *> fwriteArgs;
      fwriteArgs.push_back(beginPtr);
      fwriteArgs.push_back(new BPatch_constExpr(1));
      fwriteArgs.push_back(new BPatch_arithExpr(BPatch_minus, *currentPtr, *beginPtr));
      fwriteArgs.push_back(appImage->findVariable("outFile"));
      fwriteCall = new BPatch_funcCallExpr(*(fwriteFuncs[0]), fwriteArgs);
    }
  
    // 重置 currentPtr
    BPatch_snippet *restoreCurrentPtr =new BPatch_arithExpr(BPatch_assign, *beginPtr, *currentPtr);
  
    vector<BPatch_snippet *> prvItems;
  
    if (fwriteCall != NULL)
      prvItems.push_back(fwriteCall);
  
    prvItems.push_back(restoreCurrentPtr);
    BPatch_sequence prvAllItems(prvItems);
  
    // currentPtr < endPtr
    BPatch_boolExpr conditional(BPatch_ge, *currentPtr,*endPtr);
  
    return new BPatch_ifExpr(conditional, prvAllItems);
}

bool createAndInsertFopen(BPatch_addressSpace *app, char *path_name) {
    BPatch_image *appImage = app->getImage();
    BPatch_type *FILEPtr =bpatch.createPointer("FILEPtr", appImage->findType("FILE"));
    BPatch_variableExpr *filePointer =app->malloc(*(appImage->findType("FILEPtr")), "outFile");
  
    vector<BPatch_function *> fopenFuncs;
    appImage->findFunction("fopen", fopenFuncs);
  
    if (fopenFuncs.size() == 0) {
      fprintf(OUTCHANNEL, "error: Could not find <fopen>\n");
      return false;
    }
  
    vector<BPatch_snippet *> fopenArgs;
    BPatch_snippet *param1 = new BPatch_constExpr(path_name);
  
    // 此处使用a+而非wb+的原因是因为测试spec
    // 的test集中可能会以不同的输入多次运行该被测函数
    BPatch_snippet *param2 = new BPatch_constExpr("a+");
  
    fopenArgs.push_back(param1);
    fopenArgs.push_back(param2);
    BPatch_funcCallExpr fopenCall(*(fopenFuncs[0]), fopenArgs);
    BPatch_arithExpr fileAssign(BPatch_assign, *filePointer, fopenCall);
  
    vector<BPatch_point *> *entryPoint =find_point_of_func(appImage, "main", BPatch_entry);
  
    if (!app->insertSnippet(fileAssign, *entryPoint)) {
      fprintf(OUTCHANNEL, "error: Fail to insert <fopen>\n");
      return false;
    }
  
    return true;
  }

bool createAndInsertInitialization(BPatch_addressSpace *app) {
    BPatch_image *appImage = app->getImage();
  
    // 创建动态数组int addrsCube[0..519];
    BPatch_type *intArray = bpatch.createArray("intArray", appImage->findType("int"), 0,250); //设置为256个地址对，即512个int形式，稍微给大点520
    BPatch_variableExpr *dynAddrsCube =app->malloc(*(appImage->findType("intArray")), "addrsCube");
  
    // 创建指针变量:int *beginPtr;int *endPtr;int *currentPtr;
    BPatch_type *intPtr =bpatch.createPointer("intPtr", appImage->findType("int"));
    BPatch_variableExpr *beginPtr =app->malloc(*(appImage->findType("intPtr")), "beginPtr");
    BPatch_variableExpr *endPtr =app->malloc(*(appImage->findType("intPtr")), "endPtr");
    BPatch_variableExpr *currentPtr =app->malloc(*(appImage->findType("intPtr")), "currentPtr");
  
    //初始化指针
      // beginPtr = &addrsCube[0];指向 addrsCube 的第一个元素
    BPatch_snippet *firstElem =new BPatch_arithExpr(BPatch_ref, *dynAddrsCube, BPatch_constExpr(0));
    BPatch_snippet *beginPtrInit = new BPatch_arithExpr(BPatch_assign, *beginPtr, BPatch_arithExpr(BPatch_addr, *firstElem));
  
    // endPtr = &addrsCube[511];指向 addrsCube 的最后一个有效元素
    BPatch_snippet *lastElem =new BPatch_arithExpr(BPatch_ref, *dynAddrsCube, BPatch_constExpr(511));
    BPatch_snippet *endPtrInit = new BPatch_arithExpr(BPatch_assign, *endPtr, BPatch_arithExpr(BPatch_addr, *lastElem));
  
    // currentPtr = beginPtr;初始化 currentPtr 使其与 beginPtr 一致
    BPatch_snippet *currentPtrInit =new BPatch_arithExpr(BPatch_assign, *currentPtr, *beginPtr);
  
    // 初始化返回状态变量：bool retStatus = false;
    BPatch_variableExpr *retStatus =app->malloc(*(appImage->findType("boolean")), "retStatus");
    BPatch_snippet *retStatusInit =new BPatch_arithExpr(BPatch_assign, *retStatus, BPatch_constExpr(false));

    //组织所有初始化代码
    vector<BPatch_snippet *> items;
    items.push_back(beginPtrInit);
    items.push_back(endPtrInit);
    items.push_back(currentPtrInit);
    items.push_back(retStatusInit);
    BPatch_sequence allItems(items);
    //查找 main 函数的入口点
    vector<BPatch_point *> *points =find_point_of_func(appImage, "main", BPatch_entry);
    //插入初始化代码
    if (points->size() != 0 &&!app->insertSnippet(allItems, *points, BPatch_lastSnippet)) {
      return false;
    }
  
    return true;
  }

void findFunctionEntries(BPatch_image *appImage,vector<BPatch_function *> *funcs) {
    //获取程序的所有模块
    vector<BPatch_module *> *allModule = appImage->getModules();
    vector<BPatch_module *> useModules;
    char buffer[BUFLEN];
    //过滤掉共享库
    for (auto mm = allModule->begin(); mm != allModule->end(); mm++) {
      if (!(*mm)->isSharedLib()) {
        useModules.push_back(*mm);
      }
    }
    //检查是否所有模块都是动态库
    if (useModules.size() == 0) {
      fprintf(OUTCHANNEL, "All modules are dynamic.\n");
      return;
    }
  
    funcs->clear(); 
    //获取所有非共享库模块的函数
    for (auto pos = useModules.begin(); pos != useModules.end(); pos++) {
      vector<BPatch_function *> *tmpFuncs = (*pos)->getProcedures();
      funcs->insert(funcs->end(), tmpFuncs->begin(), tmpFuncs->end());
    }
    vector<BPatch_function *>::iterator it = funcs->begin();

  while (it != funcs->end()) {
    string func_name = (*it)->getName(buffer, BUFLEN);

    // fprintf(OUTCHANNEL, "%s\n",(*it)->getName(buffer, BUFLEN));
    // if (is_compiler_build_in(func_name))
    if (is_compiler_build_in(func_name) ) {
      it = funcs->erase(it);
    } else
      it++;
  }
    for(auto it=funcs->begin(); it!=funcs->end(); it++){
  	 fprintf(OUTCHANNEL, "%s\n", (*it)->getName(buffer, BUFLEN));
  }
    return;
}

bool get_points(BPatch_image *appImage, vector<BPatch_point *> *basicAddress) {
    int countx=0;//函数数量
    int countbasic = 0;//基本块数量
//1.获得二进制文件的所有函数
    vector<BPatch_function *> funcs;
    findFunctionEntries(appImage, &funcs);

    for (auto pf = funcs.begin(); pf != funcs.end(); pf++) {  //遍历所有函数
      if(countx++==0)  continue;
      countbasic = 0;
        char funcNameBuffer[BUFLEN];
        (*pf)->getName(funcNameBuffer, BUFLEN);//函数名
        vector<Address> dCallAddresses;
        BPatch_flowGraph *cfg = (*pf)->getCFG();//该函数的控制流程图
        set<BPatch_basicBlock *> basicblocks;
        cfg->getAllBasicBlocks(basicblocks);//该函数的基本块
        countx++;
        // cout<<"function name:"<<funcNameBuffer<<endl;
//2.遍历函数的基本块,并获得每一个基本块的最后一条指令的插桩点
        for (auto bb = basicblocks.begin(); bb != basicblocks.end(); bb++,countbasic++) {//遍历函数的基本块
            vector<Instruction> insns;
            (*bb)->getInstructions(insns);
            // if(countbasic==0||countbasic==1||countbasic==2||countbasic==3||countbasic==5||countbasic==6) continue;
            
            Instruction lastinsn = insns[insns.size() - 1]; //获取基本块的指令和最后一条指令

            Address addr = (Address)((*bb)->findExitPoint()->getAddress());//获取基本块的出口地址
            vector<BPatch_point *> tmp_points;

            if (!appImage->findPoints(addr, tmp_points)) {//在 appImage 中查找 addr 地址的插桩点
                fprintf(OUTCHANNEL,
                    "Fail to get patch point from exit address of bb.\n");
                }
            basicAddress->insert(basicAddress->end(), tmp_points.begin(), tmp_points.end());
        }
        cout<<"countx:"<<countx;
        cout<<"  countbaisc:"<<countbasic<<endl;
    }
        return true;
    }   

bool createAndInsertBasic(BPatch_addressSpace *app,vector<BPatch_point *> &basicAddress) {
  for (auto it = basicAddress.begin(); it != basicAddress.end(); ++it) {
    cout << "BPatch_point Addressdada: " << *it << endl;
  }
    BPatch_image *appImage = app->getImage();
    BPatch_variableExpr *currentPtr = appImage->findVariable("currentPtr");
    if (!currentPtr) {
    fprintf(stderr, "Error: currentPtr variable not found!\n");
    return false;
}
  
//1.插桩指令实现*currentPtr = original_address()
    BPatch_snippet *oriAddr = new BPatch_arithExpr(
    BPatch_assign, 
    BPatch_arithExpr(BPatch_deref, *currentPtr),
    BPatch_originalAddressExpr());

    fprintf(OUTCHANNEL, "-----------2-------------------\n");
//2.插桩指令实现数组指针currentPtr = currentPtr + 4;
    BPatch_snippet *currentPtrAddone = new BPatch_arithExpr(
    BPatch_assign, 
    *currentPtr,
    BPatch_arithExpr(BPatch_plus, *currentPtr, BPatch_constExpr(4)));
    fprintf(OUTCHANNEL, "-----------3-------------------\n");

    BPatch_snippet *isArrayFull = arrayFullSaveInFile(appImage);        //判断数组是否满
    
//3.把多个Dyninst 片段组合成一个顺序执行的片段
    vector<BPatch_snippet *> items;
    items.push_back(oriAddr);
    items.push_back(currentPtrAddone);
    items.push_back(isArrayFull);
    BPatch_sequence allItems(items);
//4.插桩   
    if (basicAddress.size() != 0 &&!app->insertSnippet(allItems, basicAddress, BPatch_firstSnippet)/*调用 insertSnippet进行插桩*/) {
        return false;
    }
    return true;
}


int main(int argc, char **argv) {
    int offset = 0;//命令行参数偏移量
    vector<BPatch_point *> basicAddress;//存储基本块插桩点

//1. 通过参数打开一个二进制文件,并获得目标程序的映像
    const char *mutatee_path = argv[offset + 1];
    BPatch_addressSpace *app = bpatch.openBinary(mutatee_path, true);
    if (!app) {
      fprintf(OUTCHANNEL, "openBinary failed\n");
      exit(1);
    }
    BPatch_image *appImage = app->getImage();

//2.创建一个文件路径 addr_file_path，并根据 argv[offset + 2]（输出路径）加上后缀 -re
    char addr_file_path[BUFLEN];
    strcpy(addr_file_path, argv[offset + 2]);
    strcat(addr_file_path, "-reccc");

//3.获得每一个基本块插桩点
    get_points(appImage, &basicAddress);

//4.调用 createAndInsertFopen 插桩程序，在程序开始处插入文件打开操作
    if (!createAndInsertFopen(app, addr_file_path)) {
      fprintf(OUTCHANNEL, "createAndInsertFopen failed\n");
      exit(1);
    } else {
      fprintf(OUTCHANNEL, "Fopen success\n");
    }
//5.调用 createAndInsertInitialization 插桩程序，在程序开始处插入初始化操作
    if (!createAndInsertInitialization(app)) {
      fprintf(OUTCHANNEL, "createAndInsertInitialization failed\n");
      exit(1);
    } else {
      fprintf(OUTCHANNEL, "Initialization success\n");
    }
//6.插桩
    if(createAndInsertBasic(app, basicAddress)){
      fprintf(OUTCHANNEL, "createAndInsertBasic success\n");
    }else{
      fprintf(OUTCHANNEL, "createAndInsertBasic failed\n");
    } 
//7. 结束插桩
    const char *mutatee_out_path = argv[offset + 2];
    BPatch_binaryEdit *appBin = dynamic_cast<BPatch_binaryEdit *>(app);
  
    if (appBin) {
      if (!appBin->writeFile(mutatee_out_path)) {
        fprintf(OUTCHANNEL, "write binary failed\n");
      }
    }
  }