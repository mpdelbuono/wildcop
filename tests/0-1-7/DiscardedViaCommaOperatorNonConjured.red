int foo() { return 0; };
void bar(int);

void baz()
{
   bar((foo(), foo())); // non-compliant: first foo() is discarded
}