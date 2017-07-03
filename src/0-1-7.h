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
                                                  clang::ento::check::DeadSymbols,
                                                  clang::ento::check::EndFunction>
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

        /** 
         * Called when the checker has finished a path of analysis. This is used to verify that all pending non-conjured values have been consumed.
         * Mostly this will involve checking temporaries and other trivial items.
         */
        void checkEndFunction(clang::ento::CheckerContext &C) const;
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
         * @param sourceRange the source range at which to mark the bug in output
         */
        void emitBug(clang::ento::CheckerContext &C, clang::SourceRange sourceRange) const;

        /**
         * Checks to see if the specified statement contains the specified expression. This happens most frequently
         * in compound expressions like foo(bar()) where the foo() CallExpr contains the CallExpr bar() as an argument.
         * @param statement the statement to check
         * @param expression the expression to search for
         */
        static bool statementContainsExpr(const clang::Stmt* statement, const clang::Expr* expression);

        /**
         * Removes any currently tracked known SVal expressions from the checker state if they are used by the 
         * specified expression. A transition is not automatically added to the checker context; this is because
         * all removals must happen in the same transition. (We do not want to create a branch.)
         * @param state the state to alter
         * @expression the expression against which to check for expressions pending usage
         * @returns the newly altered state
         */
        clang::ento::ProgramStateRef removeUsedExpressionsFromState(clang::ento::ProgramStateRef state, const clang::Expr* expression) const;


        /**
         * Marks the specified symbol as unused. This initiates tracking of the symbol. The symbol in its entirety is tracked, rather than
         * its constituent dependencies. This is important because the return of a structure does not necessitate use of all
         * fields of that structure; consumption of only one field in that structure is sufficient to mark the structure as used.
         * If this symbol is already being tracked, nothing happens. (This function is idempotent.)
         * @param value the value to begin tracking
         * @param C the checker context to which the state transition should be applied
         * @param originExpr the Expr from which this unused symbol originated
         */
        void markSymbolUnused(
            clang::ento::SVal value,
            clang::ento::CheckerContext &C,
            const clang::Expr* originExpr) const;


        /**
         * Marks the specified value as used. If the value depends on other symbols (such as would occur
         * in an expression), all dependent symbols are marked used.
         * @param value the value to mark as used (which may or may not be a symbol)
         * @param usedExpression the expression in which the specified value was used
         * @param C the checker context to which the state transition should be applied
         * @param sourceRange the source range with which to mark up a bug if one is detected; an invalid range is used if
         * not specified
         * @param forwardedSymbol the new, currently unused symbol that is now tracking the data that was previously
         * tracked by \see symbol, or nullptr if there is no symbol to which this is being forwarded
         */
        void markValueUsed(
            clang::ento::SVal value, 
            const clang::Expr* usedExpression,
            clang::ento::CheckerContext &C, 
            clang::SourceRange sourceRange = clang::SourceRange(),
            clang::ento::SymbolRef forwardedSymbol = nullptr) const;

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

        /**
         * The tag used when emitting a report
         */
        clang::ento::CheckerProgramPointTag tag;
    };
}