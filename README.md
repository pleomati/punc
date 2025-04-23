# Network Monitor and Firewall Tool

![App Icon](icon.ico)

A comprehensive network monitoring and firewall management tool with process control, port management, and internet speed testing capabilities.

## Features

- **Process Monitoring**: View all processes using network connections
- **Internet Access Control**: Block/allow internet access for specific processes
- **Whitelist/Blacklist Management**: Maintain lists of allowed/blocked applications
- **Port Management**: Open/close ports and set up port forwarding
- **Network Tools**: 
  - IP lookup with geolocation
  - Port scanning
  - Internet speed testing
- **Real-time Statistics**: Monitor download/upload speeds
- **Administrator Privileges**: Ensures proper functionality for firewall rules

## Installation

1. Ensure you have Python 3.8 or later installed
2. Install required packages:
   ```bash
   pip install -r requirements.txt

3. Run the application as administrator:
   ```bash
   python PUNC.py


The application has several tabs with different functionalities:
- Processes - View and manage network-connected processes
- Blocked Apps - Manage blocked applications list
- Transfers - View network transfer stats and test internet speed
- Ports - Manage port forwarding and firewall rules
- IP - IP lookup and geolocation tools

## Requirements
- Windows 7/8/10/11
- Administrator privileges for full functionality
- Internet connection for IP lookup and speed testing
	
Compiling to an executable file
To compile the program into a stand-alone .exe file (Windows):

- Requirements for compilation:
    
    ```bash
    pip install nuitka

To compile the program into a stand-alone .exe file (Windows):

- Requirements for compilation:
    
    ```bash
    pip install nuitka

- Run command:

    ```bash
    nuitka --onefile --standalone --follow-imports --windows-console-mode=disable --windows-icon-from-ico=icon.ico --include-data-files=C:\Path\to\icon.ico=icon.ico --enable-plugin=tk-inter --enable-plugin=pylint-warnings  --windows-uac-admin PUNC.py


