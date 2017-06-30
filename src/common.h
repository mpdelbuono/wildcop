/**
 * @file common.h
 *
 * Common definitions used by the framework which will end up being used in every checker file
 */
#pragma once

namespace wildcop
{
    /**
     * Type of a callback function to be used in calls to \see RegisterCheckerInitializer
     */
    typedef void(*CheckerInitializer)(clang::ento::CheckerRegistry&);

    /**
     * Registers a callback to call when clang_registerCheckers() is called at plugin load time.
     * This allows all of the checkers to be loaded by the individual checkers, and eliminates
     * the need for this file to be aware of every checker in this plugin.
     *
     * An initializer registered in this way should call to registry.addChecker<>() upon callback. This
     * callback will occur once at startup.
     * @param initializer the callback function to call at startup to register the checker
     */
    void RegisterCheckerInitializer(CheckerInitializer initializer);

    /**
     * Automatically registers the specified checker type. The appropriate way to use this function is to declare
     * a static variable within the class and then initialize it to the output of this function. The value is irrelevant,
     * but the side effect will cause the checker registration function to be registered. 
     * A static function void T::Initialize(CheckerRegistry&) must exist.
     */
    template <class T>
    int AutoInitializeChecker()
    {
        RegisterCheckerInitializer(&T::Initialize);
        return 0; // return value is irrelevant
    }
}

// Expose the public API as necessary
#ifdef _MSC_VER
#define CLANG_API extern "C" __declspec(dllexport)
#else
#define CLANG_API extern "C"
#endif

