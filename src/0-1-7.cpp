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
    const SourceRange GetSourceRange() const { return (origin->*LookupSourceRangeFunction<T>())(); }
private:
    const T* origin;
};
REGISTER_SET_WITH_PROGRAMSTATE(PendingNonLocValueSet, TrackedValueType<clang::Expr>);
REGISTER_SET_WITH_PROGRAMSTATE(PendingMemoryRegionSet, TrackedValueType<clang::ento::MemRegion>);

// For sanity
template <class T>
using PointerToMemberFunctionReturningSourceRange = clang::SourceRange(T::*)() const;

// This template provides a mechanism through which TrackedValueType<T> can determine the appropriate member function to call
template <class T> constexpr PointerToMemberFunctionReturningSourceRange<T> LookupSourceRangeFunction(); 
template <> constexpr PointerToMemberFunctionReturningSourceRange<clang::Expr> LookupSourceRangeFunction<clang::Expr>()
{
    return &clang::Expr::getSourceRange;
}
template <> constexpr PointerToMemberFunctionReturningSourceRange<clang::ento::MemRegion> LookupSourceRangeFunction<clang::ento::MemRegion>()
{
    return &clang::ento::MemRegion::sourceRange;
}

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
        markValueUsed(location, llvm::dyn_cast<const clang::Expr>(statement), C, llvm::dyn_cast<const clang::Expr>(statement));
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
        markValueUsed(value, expr, C, expr, location);
    }
}

template <class T>
ento::ProgramStateRef wildcop::DiscardedReturnValueChecker::checkSetIsEmpty(ento::ProgramStateRef state, ento::CheckerContext &C) const
{
    const auto& set = state->get<T>();
    // Exiting the top frame. All pending locs are bugs.
    if (set.isEmpty() == false)
    {
        // Emit bugs for all pending items
        for (auto value : set)
        {
            emitBug(C, value.GetSourceRange());

            // Clear it from the set so we don't keep tracking this/emit duplicates
            state = state->remove<T>(value);
        }
    }

    return state;
}

void wildcop::DiscardedReturnValueChecker::checkEndFunction(clang::ento::CheckerContext &C) const
{
    // For now we're only going to check this at the top level exit. This isn't entirely correct, but
    // it's a little tricky to attempt to identify which frame a temporary is escaping from.
    if (C.inTopFrame())
    {
        // Get the current state
        ento::ProgramStateRef state = C.getState();
        const ento::ProgramStateRef originalState = state;

        // Run the checks; emit bugs if necessary
        checkSetIsEmpty<PendingNonLocValueSet>(state, C);
        checkSetIsEmpty<PendingMemoryRegionSet>(state, C);

        // If the state was altered, record it
        if (state != originalState)
        {
            C.addTransition(state);
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

void wildcop::DiscardedReturnValueChecker::emitBug(clang::ento::CheckerContext &C, clang::SourceRange sourceRange) const
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
    const clang::Expr* forwardingExpression,
    llvm::Optional<ento::SVal> forwardedValue) const
{
    auto oldState = C.getState();
    // See if this is a symbol
    ento::SymbolRef symbol = value.getAsSymbol();

    if (symbol != nullptr)
    {
        return markSymbolUsed(symbol, C, forwardingExpression, forwardedValue);
    }
    else
    {
        // remove used expressions
        auto newState = removeUsedExpressionsFromState(oldState, usedExpression, forwardedValue);

        // if we're tracking the memory location associated with this value, mark it used as well, then forward
        const clang::ento::MemRegion* region = value.getAsRegion();
        if (region != nullptr)
        {
            TrackedValueType<ento::MemRegion> pendingMemoryRegion(region);
            if (newState->contains<PendingMemoryRegionSet>(pendingMemoryRegion))
            {
                newState = newState->remove<PendingMemoryRegionSet>(pendingMemoryRegion);

                // If we have a forwarding expression, start tracking that
                if (forwardedValue.hasValue())
                {
                    newState = forwardValueUsage(*forwardedValue, forwardingExpression, newState, C);
                }
            }
        }

        C.addTransition(newState);
    }
}

clang::ento::ProgramStateRef wildcop::DiscardedReturnValueChecker::removeUsedExpressionsFromState(
    clang::ento::ProgramStateRef state, 
    const clang::Expr* expression,
    llvm::Optional<ento::SVal> forwardedValue) const
{
    // This is not a symbol. If we're tracking it as a non-loc, remove it.
    TrackedValueType<clang::Expr> nonLoc(expression);
    if (state->contains<PendingNonLocValueSet>(nonLoc))
    {
        state = state->remove<PendingNonLocValueSet>(nonLoc);
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
            state = removeUsedExpressionsFromState(state, binop->getRHS(), forwardedValue);
        }
        else
        {
            // Not a comma operator, so handle it as per normal.
            for (auto iterator = expression->child_begin(); iterator != expression->child_end(); ++iterator)
            {
                const clang::Expr* childExpression = dyn_cast<const clang::Expr>(*iterator);
                if (childExpression)
                {
                    state = removeUsedExpressionsFromState(state, childExpression, forwardedValue);
                }
            }
        }
    }

    // forward to the specified value if it exists
    if (forwardedValue.hasValue())
    {
        const ento::MemRegion* region = forwardedValue->getAsRegion();
        if (region != nullptr)
        {
            state = state->add<PendingMemoryRegionSet>(TrackedValueType<ento::MemRegion>(forwardedValue->getAsRegion()));
        }
    }

    return state;
}

void wildcop::DiscardedReturnValueChecker::markSymbolUsed(
    ento::SymbolRef symbol,
    ento::CheckerContext &C,
    const clang::Expr* forwardingExpression,
    llvm::Optional<ento::SVal> forwardedValue) const
{
    auto state = C.getState();
    const auto originalState = state;

    // Check if we're tracking this symbol
    if (state->contains<ReturnValueMap>(symbol))
    {
        // We are, so mark it as used, and forward if necessary
        state = state->set<ReturnValueMap>(symbol, ReturnValueState::GetUsed());
        if (forwardedValue.hasValue())
        {
            state = forwardValueUsage(*forwardedValue, forwardingExpression, state, C);
        }
    }

    // Check dependent symbols
    for (auto dependencyIterator = symbol->symbol_begin(); dependencyIterator != symbol->symbol_end(); ++dependencyIterator)
    {
        // Don't need to check ourselves - we already did that
        // (This can occur on basic symbols as well as expressions)
        if (symbol != *dependencyIterator)
        {
            markSymbolUsed(*dependencyIterator, C);
            if (forwardedValue.hasValue())
            {
                state = forwardValueUsage(*forwardedValue, forwardingExpression, state, C);
            }
        }
    }

    // If we altered the state, add a transition
    if (state != originalState)
    {
        C.addTransition(state, &tag);
    }
}

ento::ProgramStateRef wildcop::DiscardedReturnValueChecker::forwardValueUsage(
    clang::ento::SVal forwardingValue, 
    const Expr* valueExpression, 
    clang::ento::ProgramStateRef state,
    clang::ento::CheckerContext& C) const
{
    // There are two types of values we can forward: symbols and memory regions
    ento::SymbolRef symbol = forwardingValue.getAsSymbol();
    if (symbol != nullptr)
    {
        // This is a symbol - add it to the map as unused
        return state->set<ReturnValueMap>(symbol, ReturnValueState::GetUnused(valueExpression->getSourceRange()));
    }
    else
    {
        const ento::MemRegion* memRegion = forwardingValue.getAsRegion();
        if (memRegion)
        {
            // This is a memory region. Start tracking it.
            TrackedValueType<ento::MemRegion> regionState(memRegion);
            if (state->contains<PendingMemoryRegionSet>(regionState))
            {
                // This memory region is already tracked! That means we're overwriting it while unused.
                // Find a reference to the old state
                for (TrackedValueType<ento::MemRegion> oldRegion : state->get<PendingMemoryRegionSet>())
                {
                    if (oldRegion == regionState)
                    {
                        // Emit a bug for this.
                        ento::ExplodedNode* errorNode = C.generateNonFatalErrorNode(state, &tag);
                        auto report = llvm::make_unique<ento::BugReport>(*bugType, "MISRA C++ 0-1-7 non-compliance: Discarding return value", errorNode);
                        report->addRange(valueExpression->getSourceRange());
                        report->addNote("return value originated here", ento::PathDiagnosticLocation(oldRegion.GetSourceRange().getBegin(), C.getSourceManager()));
                        C.emitReport(std::move(report));
                        break;
                    }
                }
            }
            return state->add<PendingMemoryRegionSet>(TrackedValueType<ento::MemRegion>(memRegion));
        }
        else
        {
            // No way to forward this usage. Return the original state.
            return state;
        }
    }
}