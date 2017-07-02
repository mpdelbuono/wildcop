/**
 * @file 0-1-7.h
 *
 * Implementation of the MISRA C++ rule 0-1-7
 */
#include "pch.h"
#include "common.h"
#include "0-1-7.h"

using namespace clang;

// Self register
const int wildcop::DiscardedReturnValueChecker::dummy = AutoInitializeChecker<DiscardedReturnValueChecker>();

void wildcop::DiscardedReturnValueChecker::Initialize(ento::CheckerRegistry& registry)
{
    registry.addChecker<DiscardedReturnValueChecker>("wildcop.0-1-7", "MISRA C++ 0-1-7: Discarded Return Value");
}

/**
 * Structure which represents the current state of a value that has been returned from a function.
 * It can be in one of two states: unused or used. A variable returned from a function starts in
 * the unused state. Once it is consumed it some way (assigned to a variable, passed in as a function argument, used
 * in a comparison, etc.) it transitions to the used state. Any value which ends its lifetime in an unused state
 * is reported as a defect.
 */
struct ReturnValueState
{
public:
    static ReturnValueState GetUnused(SourceRange& range) { return ReturnValueState(Unused, range); }
    static ReturnValueState GetUsed() { return ReturnValueState(Used, SourceRange()); }

    SourceRange GetSourceRange() const { return lastSourceRange; }
    bool IsUnused() const { return state == Unused; }

    bool operator==(ReturnValueState const &rhs) const { return state == rhs.state && lastSourceRange == rhs.lastSourceRange; }

    void Profile(llvm::FoldingSetNodeID &ID) const
    {
        ID.AddInteger(state);
    }
private:
    enum State { Unused, Used } state;
    ReturnValueState(State s, SourceRange& range) : state(s), lastSourceRange(range) {}
    SourceRange lastSourceRange;
};

REGISTER_MAP_WITH_PROGRAMSTATE(ReturnValueMap, clang::ento::SymbolRef, ReturnValueState);

wildcop::DiscardedReturnValueChecker::DiscardedReturnValueChecker()
{
    bugType.reset(new ento::BugType(this, "0-1-7 Non-compliance: Return Value Discarded", "MISRA C++"));
}

void wildcop::DiscardedReturnValueChecker::checkPreCall(const clang::ento::CallEvent &call, clang::ento::CheckerContext &C) const
{
    // We're only here to see if a tracked value is being consumed.
    // Analysis of the call's output will be handled by checkPostCall().
    for (unsigned int i = 0; i < call.getNumArgs(); ++i)
    {
        ento::SymbolRef argSymbol = call.getArgSVal(i).getAsSymbol();
        if (argSymbol == nullptr)
        {
            return;
        }

        markSymbolUsed(argSymbol, C);
    }
}

void wildcop::DiscardedReturnValueChecker::checkPostCall(const clang::ento::CallEvent &call, clang::ento::CheckerContext &C) const
{
    // If this is a call to a void function, we don't care.
    const Type* returnType = call.getResultType().getTypePtr();
    if (returnType->isVoidType())
    {
        return;
    }

    // Otherwise, let's start tracking the usage of this value
    clang::ento::SymbolRef returnValue = call.getReturnValue().getAsSymbol();
    if (returnValue == nullptr)
    {
        return; // unable to process return value from this function
    }

    // Record the newly discovered return value
    ento::ProgramStateRef currentState = C.getState();
    currentState = currentState->set<ReturnValueMap>(returnValue, ReturnValueState::GetUnused(call.getSourceRange()));
    C.addTransition(currentState);
}

void wildcop::DiscardedReturnValueChecker::checkLocation(
    ento::SVal location,
    bool isLoad,
    const Stmt *statement,
    ento::CheckerContext &C) const
{
    if (isLoad) // we only care about loaded values from tracked SVals
    {
        // Get the symbol being tracked
        ento::SymbolRef symbol = location.getAsSymbol();
        if (symbol == nullptr)
        {
            return;
        }

        // Are we tracking this symbol?
        markSymbolUsed(symbol, C, statement->getSourceRange());
    }
}

void wildcop::DiscardedReturnValueChecker::checkBind(
    clang::ento::SVal location,
    clang::ento::SVal value,
    const clang::Stmt *statement,
    clang::ento::CheckerContext &C) const
{
    // Get the symbol being loaded
    ento::SymbolRef symbol = value.getAsSymbol();
    if (symbol == nullptr)
    {
        return;
    }

    // Mark the symbol loaded. Forward if necessary.
    markSymbolUsed(symbol, C, statement->getSourceRange(), location.getAsSymbol());
}

void wildcop::DiscardedReturnValueChecker::checkDeadSymbols(clang::ento::SymbolReaper &SR, clang::ento::CheckerContext &C) const
{
    ento::ProgramStateRef state = C.getState();

    // Iterate over every tracked symbol checking to see if they're dead
    auto map = state->get<ReturnValueMap>();
    int i = 0;
    for (auto trackedSymbol : map)
    {
        ento::SymbolRef symbol = trackedSymbol.first;
        if (SR.isDead(symbol))
        {
            // check state - at this point the symbol had better be used
            if (state->get<ReturnValueMap>(symbol)->IsUnused())
            {
                // This value was never used. Report a bug.
                emitBug(C, symbol);
            }

            // always clean up the symbol from the map
            state->remove<ReturnValueMap>(symbol);
        }
    }
}

void wildcop::DiscardedReturnValueChecker::emitBug(clang::ento::CheckerContext &C, clang::ento::SymbolRef symbol) const
{
    ento::ExplodedNode *error = C.generateNonFatalErrorNode();
    if (error == nullptr)
    {
        // This has already been reached on another path - ignore it
        return;
    }

    auto report = llvm::make_unique<ento::BugReport>(*bugType, "MISRA C++ 0-1-7 non-compliance: Discarding return value", error);
    report->addRange(C.getState()->get<ReturnValueMap>(symbol)->GetSourceRange());
    report->markInteresting(symbol);
    C.emitReport(std::move(report));
}

void wildcop::DiscardedReturnValueChecker::markSymbolUsed(
    ento::SymbolRef symbol, 
    ento::CheckerContext &C, 
    clang::SourceRange sourceRange,
    ento::SymbolRef forwardedSymbol) const
{
    // Check if we're tracking this symbol
    if (C.getState()->contains<ReturnValueMap>(symbol))
    {
        // This symbol has now been used
        auto newState = C.getState()->set<ReturnValueMap>(symbol, ReturnValueState::GetUsed());
        C.addTransition(newState);
    }

    // Check dependent symbols
    for (auto dependencyIterator = symbol->symbol_begin(); dependencyIterator != symbol->symbol_end(); ++dependencyIterator)
    {
        // Don't need to check ourselves - we already did that
        // (This can occur on basic symbols as well as expressions)
        if (symbol != *dependencyIterator)
        {
            markSymbolUsed(*dependencyIterator, C);
            if (forwardedSymbol != nullptr)
            {
                auto nextState = C.getState()->set<ReturnValueMap>(forwardedSymbol, ReturnValueState::GetUnused(sourceRange));
                C.addTransition(nextState);
            }
        }
    }
}