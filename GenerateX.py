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

MAX_READ=0x513
MAX_READ_WITHOUT_NL=MAX_READ - 0x1
if(ARGC == 2):
	TO=int(sys.argv[1])
	for i in range(TO):
		STR += "%8X "
elif(ARGC == 3):
	FROM=int(sys.argv[1])
	TO=int(sys.argv[2])

	for i in range(FROM, TO):
		# add %N$8x to the string
		STR += "%" + str(i) + "$8x "
	
		# L is the added length of STR
		L=len(STR)

		# if the remaining available length is not enought for next string to add
		if( MAX_READ_WITHOUT_NL - L < (5 + len(str(i+1))) + 2):
			#print("Preparing " + str(L) + " characters")
			while(len(STR) <= MAX_READ_WITHOUT_NL - 1):
				STR += " "
			#print("Not enough room")
			# if not enough room to append something more
			print(STR)
			#print("Printed " + str(len(STR)) + " characters")
			STR="e "
	print(STR)



#print( STR )
#print( hex(len(STR)) )

