/**
 * @file 0-1-7.h
 *
 * Implementation of the MISRA C++ rule 0-1-7
 */
#include "pch.h"
#include "common.h"
#include "0-1-7.h"

#include <iostream>

// Self register
const int wildcop::DiscardedReturnValueChecker::dummy = AutoInitializeChecker<DiscardedReturnValueChecker>();

void wildcop::DiscardedReturnValueChecker::Initialize(clang::ento::CheckerRegistry& registry)
{
    std::cout << "Registration successful" << std::endl;
    registry.addChecker<DiscardedReturnValueChecker>("wildcop.0-1-7", "MISRA C++ 0-1-7: Discarded Return Value");
}

void wildcop::DiscardedReturnValueChecker::checkPreStmt(const clang::CallExpr *CE, clang::ento::CheckerContext &C) const
{
    // Currently does nothing
}
