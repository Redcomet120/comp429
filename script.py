import os
import sys
import logging

if os.path.isfile('example.log'):
    choice = raw_input('Enter a file name(Y/N): ')
    if choice.upper()[0] == 'Y':
	open('example.log', 'w').close() #erases contents of file

logging.basicConfig(filename='example.log',level=logging.DEBUG)
logging.info('This message should go to the log file') #for testing

script_path = os.path.dirname(os.path.realpath(__file__))

if len(sys.argv) != 2:
    logging.error("Usage: python <C code location>")
    sys.exit()
   
phase3_path = os.path.abspath(sys.argv[1])
word = "gcc " + phase3_path + " -o " + script_path + "/output"
print word
os.system(word)   #compile program

