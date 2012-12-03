## MF Sniffer


Script to capture unencrypted TSO login credentials              	     

**Requirements**: Python, scapy and IP/Port of mainframe           

**Created by**: Soldier of Fortran (@mainframed767)                

**Use**: Given an interface, IP and port this script will try to sniff mainframe user IDs and  passwords sent over cleartext using TN3270 (tested against x3270 and TN3270X). This scrypt does not work if the mainframe is using SSL encryption (default port 923).       
                                                                                                           

## Arguments:

  -h, --help            show this help message and exit
  
  -a IP, --ip IP        Mainframe TN3270 server IP address
  
  -p PORT, --port PORT  Mainframe TN3270 server listening port (e.g 23, 2323, 623, etc)
  
  -i INTERFACE, --interface INTERFACE network interface to listen on
  
## Screenshot
  
![ScreenShot](https://raw.github.com/mainframed/MFSniffer/master/MFSniffer-Screenshot.png)
