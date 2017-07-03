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

// For non-loc values (such as integer constants not bound to a variable), we must track that the return value
// is immediately bound to some variable or consumed (both are acceptable - as long as it is used in some way).
// We use this program trait to store that data: the most recently received set of non-loc symbols, all of which
// must be consumed prior to the next statement. Evaluation of a subsequent statement without first clearing this
// list is a bug report.
template <class T>
struct TrackedValueType
{
public:
    TrackedValueType(const T* origin) : origin(origin) {};
    bool operator ==(TrackedValueType<T> const &rhs) const { return origin == rhs.origin; }
    bool operator <(TrackedValueType<T> const& rhs) const {
        llvm::FoldingSetNodeID lhsProfile, rhsProfile;
        Profile(lhsProfile);
        rhs.Profile(rhsProfile);
        return lhsProfile < rhsProfile;
    }

    void Profile(llvm::FoldingSetNodeID &ID) const
    {
        ID.AddPointer(origin);
    }

    const T* GetOrigin() const { return origin; }
private:
    const T* origin;
};
REGISTER_SET_WITH_PROGRAMSTATE(PendingNonLocValueSet, TrackedValueType<clang::Expr>);

wildcop::DiscardedReturnValueChecker::DiscardedReturnValueChecker()
    :tag(this, "wildcop-mcpp-0-1-7")
{
    bugType.reset(new ento::BugType(this, "0-1-7 Non-compliance: Return Value Discarded", "MISRA C++"));
}

void wildcop::DiscardedReturnValueChecker::checkPreCall(const clang::ento::CallEvent &call, clang::ento::CheckerContext &C) const
{
    // We're only here to see if a tracked value is being consumed.
    // Analysis of the call's output will be handled by checkPostCall().
    for (unsigned int i = 0; i < call.getNumArgs(); ++i)
    {
        ento::SVal arg = call.getArgSVal(i);
        markValueUsed(arg, call.getArgExpr(i), C);
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
    ento::SVal returnValue = call.getReturnValue();
    markSymbolUnused(returnValue, C, call.getOriginExpr());
}

void wildcop::DiscardedReturnValueChecker::checkLocation(
    ento::SVal location,
    bool isLoad,
    const Stmt *statement,
    ento::CheckerContext &C) const
{
    if (isLoad) // we only care about loaded values from tracked SVals
    {
        // mark the symbol being loaded
        markValueUsed(location, llvm::dyn_cast<const clang::Expr>(statement), C, statement->getSourceRange());
    }
}

void wildcop::DiscardedReturnValueChecker::checkBind(
    clang::ento::SVal location,
    clang::ento::SVal value,
    const clang::Stmt *statement,
    clang::ento::CheckerContext &C) const
{
    // If this is not an expression, then it is a complex statement whose expressions we need to dive into
    const clang::Expr* expr = llvm::dyn_cast<const clang::Expr>(statement);
    if (expr == nullptr)
    {
        for (auto child : statement->children())
        {
            // Recursively check the inner statement
            checkBind(location, value, child, C);
        }
    }
    else
    {
        // Mark the symbol being loaded. Forward if necessary.
        markValueUsed(value, expr, C, statement->getSourceRange(), location.getAsSymbol());
    }
}

void wildcop::DiscardedReturnValueChecker::checkEndFunction(clang::ento::CheckerContext &C) const
{
    // For now we're only going to check this at the top level exit. This isn't entirely correct, but
    // it's a little tricky to attempt to identify which frame a temporary is escaping from.
    if (C.inTopFrame())
    {
        // Exiting the top frame. All pending locs are bugs.
        const auto& set = C.getState()->get<PendingNonLocValueSet>();
        if (set.isEmpty() == false)
        {
            // Emit bugs for all pending non-locs
            for (auto nonLoc : set)
            {
                emitBug(C, nonLoc.GetOrigin()->getSourceRange());

                // Clear it from the set so we don't keep tracking this/emit duplicates
                auto newState = C.getState()->remove<PendingNonLocValueSet>(nonLoc);
            }
        }
    }
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
            if (trackedSymbol.second.IsUnused())
            {
                // This value was never used. Report a bug.
                emitBug(C, trackedSymbol.second.GetSourceRange());
            }

            // always clean up the symbol from the map
            state->remove<ReturnValueMap>(symbol);
        }
    }
}

bool wildcop::DiscardedReturnValueChecker::statementContainsExpr(const clang::Stmt* statement, const clang::Expr* expression)
{
    // Base case - if the statement IS the expression, then return true.
    if (statement == expression)
    {
        return true;
    }
    else
    {
        // Scan all children
        for (auto iterator = statement->child_begin(); iterator != statement->child_end(); ++iterator)
        {
            if (statementContainsExpr(*iterator, expression))
            {
                return true;
            }
        }

        // Failed to find the expression
        return false;
    }
}

void wildcop::DiscardedReturnValueChecker::emitBug(clang::ento::CheckerContext &C, clang::SourceRange sourceRange/*, const clang::Decl* declWithIssue*/) const
{
    std::unique_ptr<ento::BugReport> report;

    // Try to use the specified source range if possible
    if (sourceRange.isValid())
    {
        report = llvm::make_unique<ento::BugReport>(*bugType, "MISRA C++ 0-1-7 non-compliance: Discarding return value", 
            ento::PathDiagnosticLocation(sourceRange.getBegin(), C.getSourceManager()));
        report->addRange(sourceRange);
    }
    else
    {
        // Otherwise, defer to the checker's current state
        ento::ExplodedNode *error = C.generateNonFatalErrorNode(C.getState(), &tag);
        if (error == nullptr)
        {
            // This has already been reached on another path - ignore it
            return;
        }

        report = llvm::make_unique<ento::BugReport>(*bugType, "MISRA C++ 0-1-7 non-compliance: Discarding return value", error);
    }

    // now that the report has been generated, emit it
    C.emitReport(std::move(report));
}

void wildcop::DiscardedReturnValueChecker::markSymbolUnused(
    ento::SVal value,
    ento::CheckerContext &C,
    const clang::Expr* originExpr) const
{
    // Attempt to track it as a symbol
    clang::ento::SymbolRef symbol = value.getAsSymbol();
    if (symbol == nullptr)
    {
        // This is not symbolic; probably because it's a non-loc. 
        // Record the expression as unused
        auto oldState = C.getState();
        auto newState = oldState->add<PendingNonLocValueSet>(TrackedValueType<clang::Expr>(originExpr));
        C.addTransition(newState, &tag);
    }
    else
    {
        // This is a symbol. Record it as unused.
        auto oldState = C.getState();
        auto newState = oldState->set<ReturnValueMap>(symbol, ReturnValueState::GetUnused(originExpr->getSourceRange()));
        C.addTransition(newState, &tag);
    }
}

void wildcop::DiscardedReturnValueChecker::markValueUsed(
    ento::SVal value, 
    const clang::Expr* usedExpression,
    ento::CheckerContext &C, 
    clang::SourceRange sourceRange,
    ento::SymbolRef forwardedSymbol) const
{
    auto oldState = C.getState();
    // See if this is a symbol
    ento::SymbolRef symbol = value.getAsSymbol();

    if (symbol != nullptr)
    {
        return markSymbolUsed(symbol, C, sourceRange, forwardedSymbol);
    }
    else
    {
        auto newState = removeUsedExpressionsFromState(oldState, usedExpression);
        C.addTransition(newState);
    }
}

clang::ento::ProgramStateRef wildcop::DiscardedReturnValueChecker::removeUsedExpressionsFromState(clang::ento::ProgramStateRef state, const clang::Expr* expression) const
{
    // This is not a symbol. If we're tracking it as a non-loc, remove it.
    TrackedValueType<clang::Expr> nonLoc(expression);
    if (state->contains<PendingNonLocValueSet>(nonLoc))
    {
        auto newState = state->remove<PendingNonLocValueSet>(nonLoc);
        return newState;
    }
    else
    {
        // Try to consume any subexpressions if possible

        // The comma operator is special. While expressions might be inside it, only the right argument actually ends up used. So do NOT
        // consume the left argument as if it were used.
        const clang::BinaryOperator* binop = llvm::dyn_cast<const clang::BinaryOperator>(expression);
        if (binop && binop->getOpcode() == clang::BO_Comma)
        {
            // This is a comma operator. Only consume the right-hand side.
            return removeUsedExpressionsFromState(state, binop->getRHS());
        }
        else
        {
            // Not a comma operator, so handle it as per normal.
            auto currentState = state;
            for (auto iterator = expression->child_begin(); iterator != expression->child_end(); ++iterator)
            {
                const clang::Expr* childExpression = dyn_cast<const clang::Expr>(*iterator);
                if (childExpression)
                {
                    currentState = removeUsedExpressionsFromState(currentState, childExpression);
                }
            }

            // Now that we've done all of the altering of the state in this branch, return the new state reference
            return currentState;
        }

    }
}

void wildcop::DiscardedReturnValueChecker::markSymbolUsed(
    ento::SymbolRef symbol,
    ento::CheckerContext &C,
    clang::SourceRange sourceRange,
    ento::SymbolRef forwardedSymbol) const
{
    auto oldState = C.getState();

    // Check if we're tracking this symbol
    if (oldState->contains<ReturnValueMap>(symbol))
    {
        auto newState = oldState->set<ReturnValueMap>(symbol, ReturnValueState::GetUsed());
        C.addTransition(newState, &tag);
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
                auto nextState = oldState->set<ReturnValueMap>(forwardedSymbol, ReturnValueState::GetUnused(sourceRange));
                C.addTransition(nextState, &tag);
            }
        }
    }
}