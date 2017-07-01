int foo()
{
   return 0; // SA will not create a symbol for this because it's a concrete, recognizable SVal
}

void bar()
{
   foo();
}