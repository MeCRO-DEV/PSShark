# PSShark
This is a packet capture tool using Powershell and Windows net shell. It can be used wherever installing Wireshark is impossible

Dependency:
etl2pcapng from Microsoft to convert etl file to pcap format
https://github.com/microsoft/etl2pcapng

The etl2pcapng has been embedded into the script with base64 encoding. You don't need to download it.

Usage: pscap.ps1 IF_IP_ADDRESS [WORKING_FOLDER_PATH]

Default working folder is c:\pscap

Screenshot:

![image](https://user-images.githubusercontent.com/57880343/177475077-e6cfaf56-4f00-41f1-ba2a-fc44727b15fe.png)
