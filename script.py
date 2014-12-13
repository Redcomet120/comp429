import os
import sys
import logging
import getpass

#MAIN IS TOWARDS THE BOTTOM

def execute(line):  #used to execute the program with the entered parameters
   global sudo
   global param
   global difIP
   global newIP
   global master
   script = 'script -c '
   end_script = '" results.txt > /dev/null'
   password = ""
   if sudo and not master:
        password = getpass.getpass(prompt='Please Enter your sudo password: ') #used to enter root password 
        master = True 
   if param:   #statement used when entering parameters manually
   	logging.info("Executing ./output " + line)
   	print "Executing ./output " + line
   	if sudo:
            print "Yahoo"
	    line = '"echo ' + password + ' | sudo -kS ./output ' + line
   	else:
   	    line = '"./output ' + line
   else:    #used if using Edge Cases
   	if not difIP:
	    changeIP()
        logging.info("Executing ./output " + newIP + " " + line)
   	print "Executing ./output " + newIP + " " + line
   	if sudo:
	    line = '"echo ' + password + ' | sudo -kS ./output ' + newIP + " " + line
   	else:
   	    line = '"./output ' + newIP + " " + line
   
   line = script + line + end_script   #this is the line that is executed in os.system
   #print line   
   print "Waiting until execution is complete"
   os.system(line)  

   #now reading from results file
   if not os.path.isfile('results.txt'):
        logging.error("Results file was not created properly")
	print "Results file was not created properly"
	raw_input("Press Enter to continue...")
        print "Now Returning to Menu"
        return
   oneLine = True    #To check if there is at least one line in results.txt
   success = False   #Check if expected output was found
   with open("results.txt", "r") as f:
	for line in f:
             list = line.split()
             len_list = len(list)
             if oneLine:
                logging.info("Now Reading Results")
                print "Now Reading Results"
             	oneLine = False
	     if len_list > 1:
		entropy = list[len_list - 2]
                value = list[len_list - 1]
                if entropy == 'H' or entropy == 'L':  
		    logging.info("Looks like the Program Successfully Completed")
                    print "Looks like the Program Successfully Completed"
                    logging.info(entropy + " " + value)
		    print entropy + " " + value
                    success = True
   f.close()
   if oneLine:
	logging.info("No output from the program")
	print "No output from the program"
   os.remove('results.txt')  #erase results file
   if not success:
    	logging.info("The Program Did Not Produce the Correct Output")
        print "The Program Did Not Produce the Correct Output"
   
   raw_input("Press Enter to continue...")
   print "Now Returning to Menu"
   

def logfile(): #erase contents of log file
   if os.path.isfile('example.log'):  #check if log file exists
   	open('example.log', 'w').close() #erases contents of file
        print "Log file cleared"
        return
   print "Log file doesn't exist"

def changeIP():  #used to change default IP for Edge Cases.
   global difIP
   global newIP
   newIP = raw_input('What is Default IP: ')
   if newIP.count('.') != 3:  #check for IP address
    	logging.error("Invalid IP address parameter")
    	print "Invalid IP address parameter - Returning"
        difIP = False
    	return
   difIP = True

def changeSudo():  #used to add sudo if needed to execute student's program
   global sudo
   if sudo:
	sudo = False
	print "Sudo will not be added to command line"
   else:
	sudo = True
	print "Sudo will be added to command line"

def parameters():  #when adding parameters manually, makes sure that they are correct
   inputs = raw_input('Please Enter 8 parameters: ')
   input_list = inputs.split()  # must be 8

   if len(input_list) != 8:
	logging.error("There should be 8 inputs")
    	logging.error("<IP address> <port> <entropy> <payload size> <udp sent> <ttl> <sleep time> <icmp>")
    	print "There should be 8 inputs - Returning"
    	return

   if input_list[0].count('.') != 3:  #check for IP address
    	logging.error("Invalid IP address parameter")
    	print "Invalid IP address parameter - Returning"
    	return

   if not input_list[1].isdigit():    #check port number
    	logging.error("Invalid Port Number parameter") 
    	print "Invalid Port Number parameter - Returning"
    	return

   if input_list[2] != 'H' and input_list[2] != 'L': #check entropy
    	logging.error("Invalid Entropy Value parameter")
    	print "Invalid Entropy Value parameter - Returning"
    	return

   if not input_list[3].isdigit():    #check payload size
    	logging.error("Invalid Payload Size")
    	print "Invalid Payload Size - Returning"
    	return

   if not input_list[4].isdigit():    #check number of UDP packets
    	logging.error("Invalid number of UDP packets")
    	print "Invalid number of UDP packets - Returning"
    	return

   if not input_list[5].isdigit():    #check ttl
    	logging.error("TTL is not a number")
    	print "TTL is not a number - Returning"
    	return

   ttl = int(input_list[5])

   if not (ttl > -1 and ttl < 256): #check value of ttl
    	logging.error("TTL is not within the 0 to 255 range")
    	print "TTL is not within the 0 to 255 range - Returning"
    	return

   if not input_list[6].isdigit():    #check distance between icmp messages
    	logging.error("Invalid ICMP distance amount")
    	print "Invalid ICMP distance amount - Returning"
    	return

   tail = int(input_list[6])

   if tail < 1:  #makes sure at least one tail ICMP message is sent
    	logging.error("At least one Tail ICMP message must be sent")
    	print "At least one Tail ICMP message must be sent - Returning"
    	return

   if not input_list[7].isdigit():    #check number of ICMP tail messages sent
    	logging.error("Invalid Number of ICMP tail messages")
    	print "Invalid Number of ICMP tail messages - Returning"
    	return
   
   makeLine = ""
   for x in range(0, 8): 
   	makeLine += input_list[x]
   	if x != 7:
      	   makeLine += " "
   
   execute(makeLine)

"""
START OF MAIN
"""
sudo = False
difIP = False
param = False
master = False
script_path = os.path.dirname(os.path.realpath(__file__))

if len(sys.argv) != 2:
    print "Usage: python " + sys.argv[0] + " <C code location> - Now Exiting"
    sys.exit()

logging.basicConfig(filename='example.log',level=logging.DEBUG) #setup log file

phase3_path = os.path.abspath(sys.argv[1])

if not phase3_path.endswith('.c'):
    print "Passed in file has incorrect extension - Now Exiting"
    sys.exit()

compile = "gcc " + phase3_path + " -o " + script_path + "/output"
os.system(compile)   #compile program

if not os.path.isfile('output'):  #check if compiled program exists
    print "Program could not compile correctly - Now Exiting"
    sys.exit()

z = '-1'
while z != '9':  #Main Menu
    param = False
    print ""
    if sudo:
	print "Sudo is currently enabled"
    else:
	print "Sudo is not enabled"
    print ""
    print "1 Enter Parameters"
    print "2 Edge Case:" 
    print "3 Edge Case:"
    print "4 Edge Case:"
    print "5 Edge Case:"
    print "6 Clear Log File"
    print "7 Change Sudo"
    print "8 Change IP for Edge Cases"
    print "9 Quit"
    z = raw_input('What is your choice: ')
    if z == '1':
        param = True
        parameters()
    elif z == '2':
	execute("9876 H 1100 5 255 10 50")   #these can be modified to add new edge cases
    elif z == '3':
        execute("WORD")
    elif z == '4':
        execute("WORD")
    elif z == '5':
        execute("WORD")
    elif z == '6':
	logfile()
    elif z == '7':
	changeSudo()
    elif z == '8':
        changeIP()

print "Now Exiting"

