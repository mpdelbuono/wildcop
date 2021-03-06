# Disable stricmp() warning on MSVC
add_definitions(-D_CRT_NONSTDC_NO_WARNINGS)

# Build the test binary
add_executable(wildcop-test-runner 
	main.cpp)

# Find all test folders
file (GLOB TEST_FOLDERS_GLOB RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" *)
set (TEST_FOLDERS "")
foreach(current ${TEST_FOLDERS_GLOB})
    if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${current}")
        list(APPEND TEST_FOLDERS "${current}")
    endif()
endforeach()

# For each test folder, build a list of green test cases and red test cases
foreach (current ${TEST_FOLDERS})
    file(GLOB TEST_LIST RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/${current}/" "${CMAKE_CURRENT_SOURCE_DIR}/${current}/*")
    foreach (test ${TEST_LIST})
        # find the extension and choose the right type of test
        get_filename_component(extension_dot "${CMAKE_CURRENT_SOURCE_DIR}/${current}/${test}" EXT)
        string(SUBSTRING ${extension_dot} 1 -1 extension) # strip the dot from the extension
        get_filename_component(testname "${CMAKE_CURRENT_SOURCE_DIR}/${current}/${test}" NAME_WE)
        get_filename_component(testpath "${CMAKE_CURRENT_SOURCE_DIR}/${current}/${test}" ABSOLUTE)
        get_filename_component(testdirectory "${CMAKE_CURRENT_SOURCE_DIR}/${current}/${test}" DIRECTORY)
        get_filename_component(clang "${CLANGXX_BIN}" ABSOLUTE)

        # find a temporary directory 
        if (WIN32)
            set(temppath "$ENV{TEMP}")
        else()
            set(temppath "/tmp/")
        endif()
        get_filename_component(tempfile "${temppath}/wildcop-test-output.txt" ABSOLUTE)
        file(WRITE ${tempfile} "") # clear the file 

        # add this test
        add_test(
            NAME "${current}-${testname}"
            COMMAND wildcop-test-runner ${extension} "wildcop.${current}" ${clang} $<TARGET_FILE:wildcop> ${tempfile} ${testpath}
            WORKING_DIRECTORY "${testdirectory}"
		)
    endforeach()
endforeach()
