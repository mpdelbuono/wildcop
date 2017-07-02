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
                                                  clang::ento::check::PreCall,
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
         * Called when a function call is about to be processed by the analyzer
         */
        void checkPreCall(const clang::ento::CallEvent &call, clang::ento::CheckerContext &C) const;

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
         * @param C the checker context to which the bug transition should be applied
         * @param symbol the symbol that has caused the bug to be generated
         */
        void emitBug(clang::ento::CheckerContext &C, clang::ento::SymbolRef symbol) const;

        /**
         * Marks the specified symbol as used. If the symbol depends on other symbols (such as would occur
         * in an expression), all dependent symbols are marked used.
         * @param symbol the symbol to mark as used
         * @param C the checker context to which the state transition should be applied
         * @param sourceRange the source range with which to mark up a bug if one is detected; an invalid range is used if
         * not specified
         * @param forwardedSymbol the new, currently unused symbol that is now tracking the data that was previously
         * tracked by \see symbol, or nullptr if there is no symbol to which this is being forwarded
         */
        void markSymbolUsed(
            clang::ento::SymbolRef symbol, 
            clang::ento::CheckerContext &C, 
            clang::SourceRange sourceRange = clang::SourceRange(),
            clang::ento::SymbolRef forwardedSymbol = nullptr) const;
    };
}