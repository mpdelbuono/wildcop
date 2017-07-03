int foo();
void bar(int);

void baz()
{
   bar((foo(), foo())); // non-compliant: first foo() is discarded
}