# Memory Forensics using Volatility

###  Download link : https://drive.google.com/file/d/1SrvqazzzRBVWwVVYzxwRvSBkXAk6kE50/view?usp=sharing
#### Q1. Within the binary veins of our corporate network, an automated alert triggered concern about unusual activities on a workstation. Responding promptly, our Incident Response team executed a memory dump for forensic analysis. Now at the digital precipice, the pivotal question surfaces: What profile would be most suitable for the targeted machine in our investigation?

- Using the command ```python vol.py -f bruh.raw windows.info``` we get this output:

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20050316.png)

- From this it can be determined that the profile is ```Win7SP1x86```
#### Q2. In the pursuit of understanding the incident, can you determine the total number of active processes within the memory dump?

- Using the command ```python vol.py -f bruh.raw windows.pslist | grep -c "^[0-9]"``` we output the processes into the grep command and counted the lines starting with numbers (PID)
- We get the output as ```47```

#### Q3. We have reason to believe that the user might have left a message on the system. Can you locate any textual notes within the dump?

#### Q4. Could you provide the name and PID of the process that has raised suspicion?

- Running the command ```python vol.py -f bruh.raw windows.pstree``` we a suspicion process by the name ```runddl32.exe```

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20071504.png)

- The actual windows process is of the name ```rundl32.exe``` related to the execution of dynamic link libraries (DLLs) in Windows
- Dumping the process ```python vol.py -f bruh.raw -o ./output windows.dumpfile --pid 300``` and looking up the hash outputed by ```md5sum file.0x8e905f80.0x8f050f70.DataSectionObject.runddl32.exe.dat``` on the exe file on VirusTotal we can confirm that the process is malicious

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20095657.png)