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
                                                  clang::ento::check::PreStmt<clang::CallExpr> >
    {
        template <class T>
        friend int wildcop::AutoInitializeChecker(); // to call Initialize(), which we shouldn't expose to the world
    public:
        /**
         * Performs the visitor action for a pre-statement execution on a call expression
         * @param CE the call expression that is about to be evaluated
         * @param C the current checker context
         */
        void checkPreStmt(const clang::CallExpr *CE, clang::ento::CheckerContext &C) const;
    private:
        void registerChecker(clang::ento::CheckerRegistry& registry);

        /**
         * Generates the code associated with static initializer time registration
         */
        const static int dummy;

        /**
         * Registers this class with the checker registry
         * @param registry the clang checker registry with which to register
         */
        static void Initialize(clang::ento::CheckerRegistry& registry);
    };
}