CSE 360 - Group 5

Daniel Soh
Alexa Rockwell 
Nicholas Wein 


To compile: export GRP_ID=5 
            make


Stack Smashing:

• Use a data-only-attack on the local variable authd. In particular, use stack smashing in auth to go
past the stack frame of auth into its caller’s frame, and modify the value of authd there.

To run: ./driver_smash_data

• Use a return-to-libc attack that returns to ownme. Do not hard-code the address of ownme in your
exploit. Such a technique won’t work if the base address of the executable is randomized. Instead,
read the return address off the stack (using the format string vulnerability) and then compute the
address of ownme from this information.

To run: ./driver_return_to_lib

• A simple stack smashing attack that executes injected code on the stack that calls ownme().

To run: ./driver_stack_code_injection



Format String Attack:

To run: ./driver_format_string


Heap Overflow: 

To run: ./driver_heap_code_injection
