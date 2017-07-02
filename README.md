# Wildcop Clang Plugin
The Wildcop project is a plugin that adds [MISRA C++](https://www.misra.org.uk/?TabId=171) compliance 
checking to the [clang static analyzer](https://clang-analyzer.llvm.org/). There are a wide number of 
commercial products that provide this MISRA C++ compliance check, but they are incredibly expensive. 
With the number of safety-critical projects on the rise, it is the goal of the Wildcop project to provide 
an open source compliance check to increase the accessibility of safe code and improve the safety-critical 
ecosystem as a whole.

## What is MISRA C++?
The MISRA C++ rules (formally "MISRA-C++:2008 Guidelines for the use of C++ language in critical systems")
are a copyrighted set of rules designed to increase code security, safety, and reliability. The rules are
specifically designed to be able to be checked by a static analyzer, and it is often difficult to ensure
compliance without the use of such a tool.

Conformance with MISRA C++ does not guarantee that your software works, of course. It is one tool out of
many required for a quality software process. However, it catches a lot of the most common problems associated
with safety-critical code and generally makes software more understandable to minimize the number of defects
that escape through the implementation and code review process.

## What is the clang static analyzer?
The clang static analyzer is a tool built into the clang compiler which is capable of path-sensitive analysis
of software. In short, it is a tool designed to find defects in software. "Path-sensitive" means that the static analyzer 
looks at all possible paths through the software and determines what the outcome might be. For example, consider
the following code:

```C++
int x, y;
std::cin >> x;
if (x > 5) { y = 1; }
if (x < 5) { y = 2; }
std::cout << y;
```

An average compiler can do one of two things here:
* It can warn that `y` might not be initialized, because the initialization of `y` is hidden inside of statements
controlled by an `if` expression which may or may not be true. However, a compiler that does this often cannot detect that,
when `if (x == 5) { y = 3; }` is added to the statements, all conditions have been covered, and the warning is no longer
necessary; this results in a false positive.
* It can recognize the potential of the aforementioned false positive and instead choose that it does not have enough information
to determine whether or not to emit a warning. Thus, the case is ignored and left to be found at code review, test time, or
post-release.

A static analyzer approaches this problem a different way: it makes an assumption about the value of `x`. The static analyzer, in this
particular scenario, will handle three "what-if" cases: `x > 5`, `x < 5`, and `x == 5`. When it tries the x==5 case, it will reach 
the output of `y`, determine that it is uninitialized, and emit a warning. If the `if (x == 5) { y = 3; }` statement were added, the
analyzer would find no case in which `y` was uninitialized, and it will emit no warning. Thus, the static analyzer emits no false
positive and yet has powerful defect detection built-in. 

This analysis is naturally slower than compilation. However, the analysis time is usually short enough to justify the expense, especially
after considering the hours, days, or weeks necessary for troubleshooting when something unexpectedly goes wrong (not to mention the
expenses associated with a failure in a safety-critical system).

## Supported rules
It is the goal of the Wildcop C++ project to eventually support all MISRA C++ rules that are not natively handled by the
built-in rules of the clang static analyzer or compiler. However, as this takes effort, these rules must be added one by one. The
following is the implementation status of implemented rules:

* Rule 0-1-7: In Progress

## Disclaimer
As with all MIT-licensed software, this software is provided AS-IS and WITHOUT WARRANTY. As this is not a commercial product, the
Wildcop and clang developers cannot be held responsible for any failure to detect a non-compliance, and compliance with Wildcop or
MISRA C++ rules does not guarantee software safety. Only with a robust software development process can a safety-critical system
have its risks mitigated, and the Wildcop and clang developers cannot be held responsible for any failure of that system, regardless
of any lack of diagnostics created by Wildcop or the clang static analyzer.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
IN THE SOFTWARE.
