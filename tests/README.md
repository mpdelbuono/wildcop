Tests in this folder are split by rule. The CMakeLists.txt file will build all tests accordingly. The CTest
system is used for these tests.

Tests are generally written in two ways:
* **'Red' tests** are test cases that the rule should detect and report as a diagnostic. An example is:
```C++
int x, y;
std::cin >> x;
if (x > 0) { y = 1; }
if (x < 0) { y = -1; }
std::cout << y; // diagnostic: y is uninitialized if x == 0
```
A red test should have the minimal amount of code necessary to demonstrate the test case, and should test exactly one case.
* **'Green' tests** are test cases that are close to 'Red' tests but should *not* report as a diagnostic because it is compliant code.
An example that is similar to the above red test would be as follows:
```C++
int x, y;
std::cin >> x;
if (x > 0) { y = 1; }
if (x < 0) { y = -1; }
if (x == 0) { y = 0; }
std::cout << y; // no diagnostic: no value of x can result in y uninitialized
```
Green tests should be as close as possible to red tests while remaining compliant. This allows for the exact boundary to be
tested and maximization of the test surface area.

Tests are listed in each of the rule folders. Both green and red tests are just C++ files that will be compiled by clang and run
through the static analyzer. They must be valid C++ code, which means that if, like in the above test cases, standard library
capabilities are used, then the appropriate headers must be included. However, in general it is advisable to write tests that do
not require included libraries, as this will minimize the test case and improve the speed of the test.

'Red' tests are files in the rule folders whose filenames end in .red. 'Green' tests are files in the rule folders whose filenames
end in .green. These file extensions are mandatory as CMake will use these file extensions to identify the tests. Additionally,
the folder names themselves must be the rule number exactly; the folder name will be used to verify the diagnostic reported is
for the specified rule.

Files outside of the rule folders form the testing framework and are not actual tests, themselves.