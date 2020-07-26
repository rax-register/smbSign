#!/usr/bin/python3

'''
smbSign.py version 1.0

https://github.com/rax-register/smbSign

Description: smbSign.py is a python 3 based scanner to detect whether smb signing is enabled and/or required on targets. 

By default, the script uses pysmb's smb.smbConnection class to connect to an smb server over port 445 and generate the required network traffic. Optional ports can be supplied, and in the case of port 139, pysmb's nmb.NETBIOS class to obtain the NETBIOS name of the target before executing the smb connection.

It then reads the packet data (response) from the smb server and outputs whether or not smb signing is enabled and/or required.

Dependencies:
  - pysmb  (run 'sudo pip3 install pysmb') 
  
Additional Notes: 
  - Must be run as root. Add 'sudo' to the beginning if you are not root.
  - Built and tested on Parrot OS 4.10. Also tested on Kali 2020.2.
  - Offered under the terms of the MIT License. See LICENSE file for details.

author: register
email:  bytesandorbits@gmail
'''

import argparse, os, re, signal, socket, string, subprocess, sys, time
from smb.SMBConnection import SMBConnection
from nmb.NetBIOS import NetBIOS

############################# global variables #############################


# current version
current_Ver = "1.0"

# server ip address and port variables
_server = ''
_port = 0


########################### end global variables ###########################

############################## function block ##############################


# function to receive and search through socket data for Samba server versions:
def recv_data(_sock):

    # set timeout, make the socket non-blocking, and note the starting time
    _timeout = 1
    _sock.setblocking(0)
    start_Time = time.time()
    
    # local variables to store data
    _result = ''
    part_Data = ''
    
    # loop to receive data and search it for Samba versions
    while 1:

        # if data is received, then break after timeout has been reached
        if part_Data and time.time() - start_Time > _timeout: 
            break
        
        # if data is not received, wait twice the timeout
        elif time.time() - start_Time > _timeout * 2:
            break

        _sign_Required = b"\x00\x00\x00\x00\x00\x00\x00A\x00\x03"
        _sign_Enabled = b"\x00\x00\x00\x00\x00\x00\x00A\x00\x01"

        # receive data, decode it, and then parse it for legible characters
        try:
            part_Data = _sock.recvfrom(4096)
#            print("\nraw part_Data equals: " , part_Data)  # for troubleshooting
            if _sign_Required in part_Data[0]:
                _result = '1'

            elif _sign_Enabled in part_Data[0]:
                _result = '2'

            # if we have a result, exit this function and return the info
            if _result:
#                print("Exiting loop, returning result: ", _result)  # for troubleshooting
                return _result

            else:
                time.sleep(0.1)

        except Exception as _msg:
            pass


# function to obtain NETBIOS name for use with port 139 queries
def obtain_name(_ip):

    _n = NetBIOS(broadcast=False, listen_port=0)
    ntbs_Name = _n.queryIPForName(_ip, port=137, timeout=10)
    return ntbs_Name[0]


# function to exit cleanly:
def clean_exit(_s):

    _s.close()
    sys.exit(0)


# function to deliver the bad news:
def no_soup_for_you(_come_Back_one_Year):
 
    print("==================================================")
    print("[-] Results: smb signing is enabled and required.")
    print("==================================================\n") 
 
    clean_exit(_come_Back_one_Year)


# function to deliver the good news:
def great_success(_great, _success):

    print("======================================================")
    print("[+] Results: smb signing is enabled but not required.")
    print("======================================================\n")
 
    clean_exit(_great)


# function to handle arguments on the command line:
def parser_stuff():

    global _server, _port

    # define various command line options for use
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="SMB Server IP Address (Mandatory)")
    parser.add_argument("-p", "--port", help="Optional for advanced use only: Target Port (Defaults to 445)")

    # process command line arguments               
    args = parser.parse_args()

    # remind user to include the mandatory argument if they forgot
    if not args.target:
        print("Please Specify Target IP address with -t or --target option")                        
        sys.exit(1)                 

    _server = args.target

    if not args.port:
        _port = 445

    else: 
        _port = int(args.port)

    return 0


# main function:
def main():
    
    # print version info and take care of parsing arguments
    print("smbSign.py version: ", current_Ver)
    parser_stuff()
#    _server = parser_stuff()

    # once arguments are checked, print message
    print("\n[+] Executing scan against:", _server, _port, ":")
    time.sleep(0.5)
   
    # initialize variables for SMBConnection
    _c = ''
    user_ID = ''
    _password = ''
    client_Machine_name = ''
    server_Name = ''

    # start of primary while loop:
    while True:

        try:
            # create the socket variable to store received data to parse for smb security mode detection
            _s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

            # if target port is 139, obtain the NETBIOS machine name first
            if _port == 139:
                server_Name = obtain_name(_server)
                _c = SMBConnection(user_ID, _password, client_Machine_name, server_Name, use_ntlm_v2=True, sign_options=2, is_direct_tcp=False)


            # establish SMB connection using blank credentials (anonymous), good for port 445 scans
            else:
                _c = SMBConnection(user_ID, _password, client_Machine_name, server_Name, use_ntlm_v2=True, sign_options=2, is_direct_tcp=True)

            print("    [+] Attempting to establish SMB connection.")
            time.sleep(1.0)
            _c.connect(_server, _port)
            print("    [+] SMB connection established.")
            time.sleep(0.5)
        
            # call the function to receive and process data
            print_Data = recv_data(_s)
#            print("print Data = ", print_Data)  # for troubleshooting
            _s.close()
            _c.close

            # call the appropriate function to display the results
            if print_Data == '1':
                no_soup_for_you(_s)

            elif print_Data == '2':
                great_success(_s, print_Data)

        # display an error and exit cleanly if a socket connection cannot be established
        except socket.error as msg:
            print("[-] Unable to create socket:", msg)
            clean_exit(_s)

        # handle smb connection errors
        except Exception:
            print("[-] Hit an error: ", Exception)
            clean_exit(_s)

        # handle user initiated Ctrl+c interrupts
        except KeyboardInterrupt:
            print("[-] Interrupt received. Cleaning up, then ending program.")
            clean_exit(_s)

############################ end function block ############################


# Engage!
main()
