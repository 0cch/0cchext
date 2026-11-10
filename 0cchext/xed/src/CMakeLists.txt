add_library(libxed STATIC
    BranchInst.cpp
    BranchInst.h
    MnemonicTable.cpp
    MnemonicTable.h
    Operand.cpp
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
)

target_compile_features(libxed PUBLIC cxx_std_17)
target_compile_definitions(libxed PUBLIC XEDPARSE_STATIC PRIVATE UNICODE _UNICODE)
target_include_directories(libxed PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(libxed PUBLIC xed_runtime)
if(0CCHEXT_USE_XED_2026)
    target_compile_definitions(libxed PUBLIC XEDPARSE_NEW_XED)
    add_dependencies(libxed xed2026_build)
endif()
target_compile_options(libxed PRIVATE /W3 /utf-8 /wd4996 /wd4267 /wd4244 /wd4334)
set_target_properties(libxed PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)
