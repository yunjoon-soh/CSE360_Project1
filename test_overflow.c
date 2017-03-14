#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct data {
	char name[64];
};

struct fp {
	int (*fp)();
};

void winner() {
	printf("winner\n");
}

void nowinner(){
	printf("no winner\n");
}

int main(int argc, char **argv){
	struct data *d;
	struct fp *f;

	d = malloc(sizeof(struct data));
	f = malloc(sizeof(struct fp));
	f->fp = nowinner;

	f->fp();
}