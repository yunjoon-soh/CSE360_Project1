#!/usr/bin/python

import sys

ARGC=len(sys.argv) # python does not have argc

if(ARGC < 2):
	print 'Usage: ' + sys.argv[0] + ' [NUMBER OF %08X]'
	print 'Usage: ' + sys.argv[0] + ' [STARTING NUMBER I FOR %I$8X] [ENDING NUMBER J FOR %J$8X]'
	exit(1)

# base of the string
STR="e "

# NEW_LINE=4 # \n does not work for pretty print, instead adjust the terminal width
# CNT=0

MAX_READ=0x116
MAX_READ_WITHOUT_NL=0x115
if(ARGC == 2):
	TO=int(sys.argv[1])
	for i in range(TO):
		STR += "%8X "
elif(ARGC == 3):
	FROM=int(sys.argv[1])
	TO=int(sys.argv[2])

	for i in range(FROM, TO):
		STR += "%" + str(i) + "$8x "
	#	if( CNT % NEW_LINE == 0):
	#		STR += "\\n"
	#	CNT += 1
	
		L=len(STR)
		if( MAX_READ_WITHOUT_NL - L <= (5 + len(str(i)))):
			while(len(STR) < MAX_READ_WITHOUT_NL):
				STR+=' '
			# if not enough room to append something more
			print(STR)
			STR="e "
	print(STR)



#print( STR )
#print( hex(len(STR)) )

