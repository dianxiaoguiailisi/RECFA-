# DYNINST_INCLUDE and DYNINST_LIB should be set to locations
# where Dyninst header and library files were installed, respectively
# 目标文件
T=DyninstBasicAdd

# 
SOURCES=DyninstBasicAdd.cc

OBJECTS=$(SOURCES:.c=.o)
# 编译器
CC=g++

# 依赖库
LIBS =  -ldyninstAPI -lboost_system -linstructionAPI -lparseAPI -lcommon -lsymtabAPI  -L$(DYNINST_LIB) #-L/usr/local/lib

HEADERS = -I$(DYNINST_INCLUDE) #-I/usr/local/include

# 编译选项
FLAGS = $(LIBS) $(HEADERS) -std=c++11 -no-pie -g

$(T): $(OBJECTS)
	$(CC) -o $(T) $(OBJECTS) $(FLAGS)
	
%.o: %.c
	$(CC) -c -o $@ $< $(FLAGS)

clean:
	rm -rf $(T) *.o 





