add_executable(text_utils_tests
    unit/text_utils_test.cpp
    "${CMAKE_SOURCE_DIR}/0cchext/text_utils.cpp"
)
target_include_directories(text_utils_tests PRIVATE
    "${CMAKE_SOURCE_DIR}/0cchext"
    "${WINDOWS_SDK_INCLUDE_DIR}"
    "${WINDBG_ENGEXTCPP_INCLUDE_DIR}"
)
cchext_configure_project_target(text_utils_tests)
add_test(NAME text_utils COMMAND text_utils_tests)

add_executable(assembler_tests
    unit/assembler_test.cpp
    "${CMAKE_SOURCE_DIR}/0cchext/assembler_backend.cpp"
)
target_include_directories(assembler_tests PRIVATE
    "${CMAKE_SOURCE_DIR}/0cchext"
    "${CMAKE_SOURCE_DIR}/0cchext/xed/src"
    "${CMAKE_SOURCE_DIR}/0cchext/xed/xed2/include"
    "${WINDOWS_SDK_INCLUDE_DIR}"
    "${WINDBG_ENGEXTCPP_INCLUDE_DIR}"
)
target_compile_definitions(assembler_tests PRIVATE XEDPARSE_STATIC UNICODE _UNICODE)
target_link_libraries(assembler_tests PRIVATE libxed)
set_target_properties(assembler_tests PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)
add_test(NAME assembler COMMAND assembler_tests)
