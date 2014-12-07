import os
import sys
import logging

def edge():
   print "Yahoo"
   sys.exit()

if len(sys.argv) != 2:
    logging.error("Usage: python <C code location>")
    sys.exit()

if os.path.isfile('example.log'):  #check if log file exists
    choice = raw_input('Do you want to erase the contents of the log file(Y/N): ')
    if choice.upper()[0] == 'Y':
        open('example.log', 'w').close() #erases contents of file

logging.basicConfig(filename='example.log',level=logging.DEBUG)
logging.info('This message should go to the log file') #for testing

script_path = os.path.dirname(os.path.realpath(__file__))

phase3_path = os.path.abspath(sys.argv[1])

if not phase3_path.endswith('.c'):
    logging.error("Passed in file has incorrect extension")
    print "Error encountered - exiting"
    sys.exit()

compile = "gcc " + phase3_path + " -o " + script_path + "/output"
#print compile
os.system(compile)   #compile program

choice = raw_input('Start Edge Cases(Y/N): ') #for edge cases
if choice.upper()[0] == 'Y':
    edge()

script_path = os.path.dirname(os.path.realpath(__file__))
   
inputs = raw_input('Please 8 parameters: ')
input_list = inputs.split()  # must be 8

if len(input_list) != 8:
    logging.error("There should be 8 inputs")
    logging.error("<IP address> <port> <entropy> <payload size> <udp sent> <ttl> <sleep time> <icmp>")
    print "Error encountered - exiting"
    sys.exit()

if input_list[0].count('.') != 3:  #check for IP address
    logging.error("Invalid IP address parameter")
    print "Error encountered - exiting"
    sys.exit()

if not input_list[1].isdigit():    #check port number
    logging.error("Invalid Port Number parameter") 
    print "Error encountered - exiting"
    sys.exit()

if not (input_list[2] != 'H' or input_list[2] != 'L'):
    logging.error("Invalid Entropy Value parameter")
    print "Error encountered - exiting"
    sys.exit()

if not input_list[3].isdigit():    #check payload size
    logging.error("Invalid Payload Size")
    print "Error encountered - exiting"
    sys.exit()

if not input_list[4].isdigit():    #check number of UDP packets
    logging.error("Invalid number of UDP packets")
    print "Error encountered - exiting"
    sys.exit()

if not input_list[5].isdigit():    #check ttl
    logging.error("TTL is not a number")
    print "Error encountered - exiting"
    sys.exit()

ttl = int(input_list[5])

if not (ttl > -1 and ttl < 256): #check value of ttl
    logging.error("TTL is not within the 0 to 255 range")
    print "Error encountered - exiting"
    sys.exit()

if not input_list[6].isdigit():    #check distance between icmp messages
    logging.error("Invalid ICMP distance amount")
    print "Error encountered - exiting"
    sys.exit()

tail = int(input_list[6])

if tail < 1:
    logging.error("At least one Tail ICMP message must be sent")
    print "Error encountered - exiting"
    sys.exit()

if not input_list[7].isdigit():    #check number of ICMP tail messages sent
    logging.error("Invalid Number of ICMP tail messages")
    print "Error encountered - exiting"
    sys.exit()

execute = ""
for x in range(0, 8): 
   execute += input_list[x]
   if x != 7:
      execute += " "

execute = "./output " + execute
print "It's Time"
#os.system(./output  

