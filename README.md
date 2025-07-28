This project is dedicated to the 14 Yuenglings that proudly served and lost their lives to produce this project.

# Overview 
This is an extremely unsafe project built to allow users to make Windows syscalls through a simple API while obfuscating the return address with a user defined ROP chain discovered at runtime. Outside of the procedural macro for API hashing it has no dependencies, makes no heap allocations, and can be compiled directly to position independent shellcode.

# Features
* Simple and easy Windows function calls, indirect Syscalls, or indirect Syscalls via JOP/ROP chain
* Runtime executable memory scanning for user defined ROP or JOP gadgets. You can build chains of up to 5 of them to execute your syscalls.
* IAT obfuscation. Use whatever functions you want without getting flagged!
* User defineable hashing function to allow custom implementations. You don't need to worry about anyone running strings on your tool.
* No heap allocations and no standard library. You can compile anything made with this directly to shellcode.
* Near-zero memory safety. You get to experience the joy of tracing any errors through WinDbg for hours.
