/**
 * @file plugin.cpp
 *
 * Main entry point for the plugin module. In this file is contained the various functions required
 * to register the plugin with clang
 */

#include "pch.h"
#include "common.h"

using namespace clang;
using namespace ento;

namespace wildcop
{
    namespace
    {
        /**
         * Stores all of the currently-registered callbacks. This will be queried when clang_registerCheckers() is called.
         */
        std::vector<CheckerInitializer> callbacks;
    }

    void RegisterCheckerInitializer(CheckerInitializer initializer)
    {
        // register the provided initializer
        callbacks.push_back(initializer);
    }
}

// Register with clang
CLANG_API
void clang_registerCheckers(CheckerRegistry &registry) {
    // Run through the vector of initializers and call them all
    for (std::vector<wildcop::CheckerInitializer>::const_iterator iter = wildcop::callbacks.begin();
         iter != wildcop::callbacks.end();
         ++iter)
    {
        // call the initializer
        (*iter)(registry);
    }
}

CLANG_API
const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;