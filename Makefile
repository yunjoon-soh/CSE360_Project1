CFLAGS=-g -Wall -m32 -DGRP=$(GRP_ID) -DLEN1=1021 -DLEN2=256 -DLEN3=1000 -DRANDOM=0
#CFLAGS=-g -Wall -DLEN1=1021 -DLEN2=256 -DLEN3=1000 -DRANDOM=random\(\)

all: vuln.s vuln driver driver_authd_expl alexa_expl dan_expl

vuln: vuln.o my_malloc.o
	gcc $(CFLAGS) -o vuln vuln.o my_malloc.o
	execstack -s vuln

vuln.o: padding.h vuln.c my_malloc.h
	gcc $(CFLAGS) -c vuln.c

vuln.s: vuln.c my_malloc.h
	gcc $(CFLAGS) -DASM_ONLY -Wa,-adhln -c vuln.c > vuln.s
	rm vuln.o

my_malloc.o: my_malloc.h my_malloc.c
	gcc $(CFLAGS)  -c my_malloc.c

driver: driver.c
	gcc $(CFLAGS) -o driver driver.c

driver_authd_expl: driver_authd_expl.c
	gcc $(CFLAGS) -o driver_authd_expl driver_authd_expl.c

alexa_expl: alexa_expl.c
	gcc $(CFLAGS) -o alexa_expl alexa_expl.c

dan_expl: dan_expl.c
	gcc $(CFLAGS) -o dan_expl dan_expl.c

padding.h:
	./mkpad $(GRP_ID)

clean:
	rm -f vuln vuln.o my_malloc.o vuln.s padding.h driver_authd_expl driver alexa_expl dan_expl
