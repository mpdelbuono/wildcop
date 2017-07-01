/**
 * @file 0-1-7.h
 *
 * Defines the checker for MISRA C++ Rule 0-1-7
 */
#pragma once
#include "common.h"

namespace wildcop
{
    class DiscardedReturnValueChecker : public clang::ento::Checker<
                                                  clang::ento::check::PostCall,
                                                  clang::ento::check::Location,
                                                  clang::ento::check::Bind,
                                                  clang::ento::check::DeadSymbols>
    {
        template <class T>
        friend int wildcop::AutoInitializeChecker(); // to call Initialize(), which we shouldn't expose to the world
    public:
        /**
         * Constructs a new DiscardedReturnValueChecker
         */
        DiscardedReturnValueChecker();

        /**
         * Called when a function call occurs and has been processed by the analyzer
         */
        void checkPostCall(const clang::ento::CallEvent &call, clang::ento::CheckerContext &C) const;

        /**
         * Called when a location is accessed
         */
        void checkLocation(clang::ento::SVal location, bool isLoad, const clang::Stmt *statement, clang::ento::CheckerContext &C) const;

        /**
         * Called when a value is assigned to another value
         */
        void checkBind(clang::ento::SVal location, clang::ento::SVal value, const clang::Stmt *statement, clang::ento::CheckerContext &C) const;

        /**
         * Called when a symbol becomes dead. The DiscardedReturnValueChecker will use this callback to both clean up the symbol
         * and verify that the symbol has reached the 'Used' state.
         */
        void checkDeadSymbols(clang::ento::SymbolReaper &SR, clang::ento::CheckerContext &C) const;
    private:
        /**
         * BugType object for use in emitting checker diagnostics
         */
        mutable std::unique_ptr<clang::ento::BugType> bugType;

        /**
         * Generates the code associated with static initializer time registration
         */
        const static int dummy;

        /**
         * Registers this class with the checker registry
         * @param registry the clang checker registry with which to register
         */
        static void Initialize(clang::ento::CheckerRegistry& registry);

        /**
         * Emits a bug report to the checker context. Called whenever the checker analysis fails.
         */
        void emitBug(clang::ento::CheckerContext &C, clang::ento::SymbolRef symbol) const;
    };
}