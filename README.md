#CSE 360 - Group 5

Daniel Soh, Alexa Rockwell, Nicholas Wein 

## Compile
* To compile: export GRP_ID=5 && make

### Stack Smashing:

 1. Use a data-only-attack on the local variable authd. In particular, use stack smashing in auth to go past the stack frame of auth into its caller’s frame, and modify the value of authd there. 

	* To run: ./driver_smash_data

 2. Use a return-to-libc attack that returns to ownme. Do not hard-code the address of ownme in your exploit. Such a technique won’t work if the base address of the executable is randomized. Instead, read the return address off the stack (using the format string vulnerability) and then compute the address of ownme from this information. 

	* To run: ./driver_return_to_libc

 3. A simple stack smashing attack that executes injected code on the stack that calls ownme().

	* To run: ./driver_stack_code_injection

### Format String Attack:

* To run: ./driver_format_string

### Heap Overflow: 

* To run: ./driver_heap_code_injection

## Files

### Script
* GenerateX.py
: Helper script to dump stack using format string vulnerability
: Typical usage: ./GenerateX.py 1 100 | ./vuln

### Notes
* Heap
: Notes and info gathered about the heap

* Stack
: Notes and info gathered about the stack

### Misc
* Makefile

* README.md

* miniproj.pdf
: project description

* mkpad


### Samples provided by professor
* driver.c
* driver_authd_expl.c

### Exploits
* driver_format_string.c
* driver_heap_code_injection.c
* driver_return_to_libc.c
* driver_smash_data.c
* driver_stack_code_injection.c

### Assembly codes
* jmp_heap_ownme.s
: Code used for driver_heap_code_injection

* jmp_ownme.s
: Code used for stack code injection

### Vulnerable codes
* my_malloc.c
* my_malloc.h
* vuln.c
