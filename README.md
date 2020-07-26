# smbSign
python3 scanner to detect smb security mode

Description:


    smbSign.py version 1.0

    https://github.com/rax-register/smbSign

    Description: smbSign.py is a python 3 based scanner to detect whether smb signing is enabled and/or required on targets. 

    By default, the script uses pysmb's smb.smbConnection class to connect to an smb server over port 445 and generate the required network traffic. 
	
    Optional ports can be supplied, and in the case of port 139, pysmb's nmb.NETBIOS class to obtain the NETBIOS name of the target before executing the smb connection.

    It then reads the packet data (response) from the smb server and outputs whether or not smb signing is enabled and/or required.

    Dependencies:
      - pysmb  (run 'sudo pip3 install pysmb') 
  
    Additional Notes: 
      - Must be run as root. Add 'sudo' to the beginning if you are not root.
      - Built and tested on Parrot OS 4.10. Also tested on Kali 2020.2.
      - Offered under the terms of the MIT License. See LICENSE file for details.

    author: register
    email:  bytesandorbits@gmail



Usage:

    $sudo python3 smbSign.py -h
    smbSign.py version:  1.0
    usage: smbSign.py [-h] [-t TARGET] [-p PORT]
    
    optional arguments:
      -h, --help            show this help message and exit
      -t TARGET, --target TARGET
                            SMB Server IP Address (Mandatory)
      -p PORT, --port PORT  Optional for advanced use only: Target Port (Defaults to 445)

    $sudo python3 smbSign.py -t 192.168.110.51
    smbSign.py version:  1.0
    
    [+] Executing scan against: 192.168.110.51 445 :
        [+] Attempting to establish SMB connection.
        [+] SMB connection established.
    ======================================================
    [+] Results: smb signing is enabled but not required.
    ======================================================


    $sudo python3 smbSign.py -t 192.168.110.51 -p139
    smbSign.py version:  1.0
    
    [+] Executing scan against: 192.168.110.51 139 :
        [+] Attempting to establish SMB connection.
        [+] SMB connection established.
    ======================================================
    [+] Results: smb signing is enabled but not required.
    ======================================================

