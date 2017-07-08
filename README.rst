Stacker
=======

In small embedded systems, memory is generally a very scarce resource. Most
memory usage can be controlled and checked at compile time, by avoiding
``malloc()`` and instead using fixed-size values in .bss. If a dynamic
allocator is used, it is difficult to predict how much memory is "actually
necessary", but code can detect when an allocation fails due to lack of
memory and act accordingly.

The one remaining way memory can be used is on the stack. Local variables
that cannot fit in registers and saved state around function calls are all
placed on the stack in a stack frame produced by each function on entry
and removed on exit. The stack is, in some sense, another general-purpose
memory allocator: allocation is performed by calling a function, and memory
is freed when the function that calls it returns.

Some constructs in C allow arbitrary amounts of memory to be alocated on
the stack, determined at runtime. Local variables in a recursive function
are instantiated for every call to that function, and there can be any
number of such calls. The ``alloca()`` function and variable-length arrays
(standard in C99 and supported in many earlier compilers) can change the size
of a stack frame at runtime. Clearly, it is not possible to write a tool
to accurately bound the stack usage of *any* C program; this is prohibited
by the implications of Rice's theorem and the *Entscheidungsproblem*.

Fortunately, a few restrictions allow us to avoid undecidability. A program
in most procedural languages like C can be viewed as a graph of functions:
each function has an edge to every other function that it might possibly
call. We make the assumption that every call not optimized away by the
compiler is a call that might happen at runtime. The *call graph* starts at
the first function executed by the program. If the call graph is cyclic, the
program might recurse; otherwise, every possible call path can be enumerated
and analyzed separately.

Function Analysis
-----------------

A very simple compiled function has a structure something like:

* Allocate some space on the stack
* Perform computation, possibly calling other functions
* Free the allocated stack space
* Return

In practice, this is complicated in several ways. Allocating stack space is
performed along with saving call-saved registers using "push" instructions,
as well as by manipulating the stack pointer directly, and (on some
architectures) also during "call" instructions; freeing of space happens
through several mechanisms as well. To improve performance at the expense of
code size, compilers may duplicate parts of the end of a function's code, so
a function may have many return sites. Finally, some function calls are
implemented by the compiler as "tail calls": they occur *after* a function's
stack frame has been freed. (Tail call optimization was developed to allow
recursive functions to be compiled efficiently, but it helps reduce stack
usage even in non-recursive programs.)

Stacker analyzes functions by first parsing the assembly produced by the
compiler and identifying function names and boundaries. Then, instructions
are translated into a machine-independent form, and instructions not
relevant to inter-function control flow or stack usage are filtered out.
This turns a function into a stream of pseudo-operations like "change stack
usage" (specified with a positive or negative delta), "call", "tail-call",
etc. Then, Stacker parses these sequences against its understanding of
function idioms produced by compilers, like return site duplication. Each
function is reduced to a number of bytes of stack usage, a set of possible
callees, and a set of possible tail-callees. At this point, Stacker can
assemble the call graphs in the program, and find the total stack space
used by the longest such path.
