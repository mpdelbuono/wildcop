int foo();
int bar(int);

void baz()
{
   bar(foo() + 1); // non-compliant: bar() return value discarded
}