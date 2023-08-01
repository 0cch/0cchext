project(libxed)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd\"4996\"")

ADD_DEFINITIONS(-DUNICODE)
ADD_DEFINITIONS(-D_UNICODE)
ADD_DEFINITIONS(-DXEDPARSE_STATIC)

ADD_LIBRARY(libxed STATIC 
    Operand.h
    OperandMem.cpp
    OperandMem.h
    OperandSegSel.cpp
    OperandSegSel.h
    OpSize.cpp
    OpSize.h
    Parser.cpp
    Parser.h
    ParseTest.cpp
    parsetest.h
    Prefix.cpp
    Prefix.h
    Register.cpp
    Register.h
    RegisterTable.h
    Translator.cpp
    Translator.h
    Validator.cpp
    Validator.h
    XEDParse.cpp
    XEDParse.h
    BranchInst.cpp
    BranchInst.h
    MnemonicTable.cpp
    MnemonicTable.h
    Operand.cpp
)