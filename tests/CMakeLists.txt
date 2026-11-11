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
find_program(PWSH_EXECUTABLE NAMES pwsh)
if(PWSH_EXECUTABLE)
    add_test(NAME agent_mcp
        COMMAND "${PWSH_EXECUTABLE}" -NoProfile -File
            "${CMAKE_CURRENT_SOURCE_DIR}/agent/mcp-smoke.ps1"
            -AgentExe "$<TARGET_FILE:0cchext-agent>"
    )
    add_test(NAME agent_mcp_session
        COMMAND "${PWSH_EXECUTABLE}" -NoProfile -File
            "${CMAKE_CURRENT_SOURCE_DIR}/agent/mcp-session-smoke.ps1"
            -AgentExe "$<TARGET_FILE:0cchext-agent>"
    )
endif()
