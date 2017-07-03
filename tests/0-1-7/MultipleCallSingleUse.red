int foo();
void baz(int);

void bar()
{
   int a = foo();
   a = foo();
   baz(a);
}