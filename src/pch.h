/**
 * @file pch.h
 *
 * Precompiled header for the Wildcop plugin
 */

// These include file have various warnings in MSVC. Disable them
#ifdef _MSC_VER
    #pragma warning(push)
    #pragma warning(disable:4146)
    #pragma warning(disable:4244)
    #pragma warning(disable:4141)
    #pragma warning(disable:4291)
    #pragma warning(disable:4996)
    #pragma warning(disable:4267)
    #define WILDCOP_WARNING_POP() __pragma(warning(pop))
#else
    #define WILDCOP_WARNING_POP()
#endif //defined(_MSC_VER)

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
WILDCOP_WARNING_POP()
