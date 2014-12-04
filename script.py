import os
import sys
import logging

def edge():
   print "Yahoo"

if os.path.isfile('example.log'):
    choice = raw_input('Enter a file name(Y/N): ')
    if choice.upper()[0] == 'Y':
	open('example.log', 'w').close() #erases contents of file

choice = raw_input('Start Edge Cases(Y/N): ') #for edge cases
if choice.upper()[0] == 'Y':
    edge()

logging.basicConfig(filename='example.log',level=logging.DEBUG)
logging.info('This message should go to the log file') #for testing

script_path = os.path.dirname(os.path.realpath(__file__))

if len(sys.argv) != 2:
    logging.error("Usage: python <C code location>")
    sys.exit()
   
phase3_path = os.path.abspath(sys.argv[1])
compile = "gcc " + phase3_path + " -o " + script_path + "/output"
#print compile
os.system(compile)   #compile program

print "<IP address> <port> <entropy> <payload size> <udp sent> <ttl> <sleep time> <icmp>"
inputs = raw_input('Please enter the inputs: ')
input_list = inputs.split()  # must be 8

if len(input_list) != 8
    logging.error("There should be 8 inputs")
