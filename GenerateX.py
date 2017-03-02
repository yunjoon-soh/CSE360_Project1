#!/usr/bin/python

import sys

ARGC=len(sys.argv) # python does not have argc

if(ARGC < 2):
	print 'Usage: ' + sys.argv[0] + ' [NUMBER OF %08X]'
	exit(1)

# base of the string
STR="e "

# NEW_LINE=4 # \n does not work for pretty print, instead adjust the terminal width
# CNT=0

if(ARGC == 2):
	TO=int(sys.argv[1])
	for i in range(TO):
		STR += "%8X "
elif(ARGC == 3):
	FROM=int(sys.argv[1])
	TO=int(sys.argv[2])

	for i in range(FROM, TO):
		STR += "%" + str(i) + "$8X "
	#	if( CNT % NEW_LINE == 0):
	#		STR += "\\n"
	#	CNT += 1
		if( len(STR) >= 0x113 ):
			print(STR)
			STR="e "

#print( STR )
#print( hex(len(STR)) )

