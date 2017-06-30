int foo()
{
   return 0;
}

void bar()
{
   foo(); // non-compliant: 0-1-7
}
