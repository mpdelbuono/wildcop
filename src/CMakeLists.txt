include_directories(AFTER SYSTEM "${LLVM_ROOT_DIR}/include")
link_directories("${LLVM_ROOT_DIR}/lib")

# Create the target
add_library(wildcop MODULE
    plugin.cpp
)
target_link_libraries(wildcop
    clangAST
)