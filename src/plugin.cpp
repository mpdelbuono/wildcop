/**
 * @file plugin.cpp
 *
 * Main entry point for the plugin module. In this file is contained the various functions required
 * to register the plugin with clang
 */

#include "pch.h"

using namespace clang;
using namespace ento;


// Register with clang
extern "C"
void clang_registerCheckers(CheckerRegistry &registry) {
    // No checkers yet!
}

extern "C"
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;