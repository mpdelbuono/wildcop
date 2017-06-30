/**
 * @file main.cpp
 *
 * Entry point for the Wildcop test suite. This lightweight test suite runs the clang compiler with
 * a specified plugin and checks to see if the appropriate diagnostic is reported. The command line parameters
 * are inherently cumbersome to use because it is easier to develop that way and this tool is only intended 
 * to be used by the CTest system building the Wildcop project. As such, it does not need to be human-readable.
 */

#include <iostream>
#include <sstream>

enum ExitCodes
{
    EXIT_CODE_SUCCESS,
    EXIT_CODE_FAILURE,
    EXIT_CODE_ERROR
};

enum Arguments
{
    ARG_SELF,
    ARG_TYPE,
    ARG_RULENAME,
    ARG_CLANGPATH,
    ARG_PLUGINPATH,
    ARG_TESTPATH,

    // Always last:
    ARG_NUMBER_OF_ARGUMENTS
};

/**
 * Entry point of the application. Arguments are as follows:
 *   1. Type of test. Can be 'green' or 'red'
 *   2. Checker rule name. Only this checker will be enabled.
 *   3. Absolute path to clang++, including the executable name
 *   4. Absolute path to plugin
 *   5. Absolute filename of the test case. Should be a C++ file.
 *
 * Exit codes are as follows:
 *   0: Test case succeeded (i.e., no diagnostic in a 'green' case, or appropriate diagnostic in a 'red' case)
 *   1: Test case failed (i.e., diagnostic in a 'green' case, or no appropriate diagnostic in a 'red' case)
 *   2: Test case setup failure. In this case, the test case did not run (completely), and instead the framework encountered
 *      an error while running.
 */
int main(int argc, const char* argv[])
{
    std::cout << "----" << std::endl;
    // Verify all arguments are present
    if (argc != ARG_NUMBER_OF_ARGUMENTS)
    {
        std::cerr << "Incorrect number of arguments" << std::endl;
        std::cerr << "Usage: " << argv[ARG_SELF] << " <type> <checker> <clang> <plugin> <file>" << std::endl;
        return EXIT_CODE_ERROR;
    }

    // Build the clang command
    std::stringstream commandBuilder;
    commandBuilder << argv[ARG_CLANGPATH] << " "    // Not using quotes here because of a problem with system() on Windows. At some point
        << "--analyze "                             // later we need to figure out how to handle this gracefully: https://stackoverflow.com/questions/9964865/
        << "-fplugin=\"" << argv[ARG_PLUGINPATH] << "\" "
        << "-x c++ -std=c++14 "
        << "\"" << argv[ARG_TESTPATH] << "\" "
        << "-Xanalyzer -analyzer-checker=" << argv[ARG_RULENAME];
    std::string command = commandBuilder.str();

    // Figure out the result we expect
    int expected;
    if (stricmp(argv[ARG_TYPE], "green"))
    {
        expected = 0;
    }
    else if (stricmp(argv[ARG_TYPE], "red"))
    {
        expected = 1;
    }
    else
    {
        // Don't know what type of test this is! Fail.
        std::cerr << "Unknown test type: " << argv[ARG_TYPE] << std::endl;
        return EXIT_CODE_ERROR;
    }

    // Execute it
    std::cout << command.c_str() << std::endl;
    int result = system(command.c_str());
    if (result == -1)
    {
        // An error occurred while trying to invoke the command
        std::cerr << "system() call failed" << std::endl;
        return EXIT_CODE_ERROR;
    }
    else if (result == expected)
    {
        // Test passed
        return EXIT_CODE_SUCCESS;
    }
    else
    {
        // Test failed
        return EXIT_CODE_FAILURE;
    }
}