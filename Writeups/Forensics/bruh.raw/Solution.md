# Memory Forensics using Volatility

###  Download link : https://drive.google.com/file/d/1SrvqazzzRBVWwVVYzxwRvSBkXAk6kE50/view?usp=sharing
#### Q1. Within the binary veins of our corporate network, an automated alert triggered concern about unusual activities on a workstation. Responding promptly, our Incident Response team executed a memory dump for forensic analysis. Now at the digital precipice, the pivotal question surfaces: What profile would be most suitable for the targeted machine in our investigation?

- Using the command ```python vol.py -f bruh.raw windows.info``` we get this output:

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20050316.png)

- From this it can be determined that the profile is ```Win7SP1x86```
- Volatility 2.6 gives a better output for this and the best profile is outputed to be ```Win7SP1x86_23418```

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20134503.png)

#### Q2. In the pursuit of understanding the incident, can you determine the total number of active processes within the memory dump?

- Using the command ```python vol.py -f bruh.raw windows.pslist | grep -c "^[0-9]"``` we output the processes into the grep command and counted the lines starting with numbers (PID)
- We get the output as ```47```

#### Q3. We have reason to believe that the user might have left a message on the system. Can you locate any textual notes within the dump?

- Attempted to run ```windows.strings``` on the memory dump the results were vague and pointless.
- Using the ```clipboard``` plugin in Volitlity 2.6 and running the command ```python2 vol.py -f bruh.raw --profile=Win7SP1x86_23418 clipboard``` gave an output that looks a flag 

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20120355.png)

#### Q4. Could you provide the name and PID of the process that has raised suspicion?

- Running the command ```python vol.py -f bruh.raw windows.pstree``` we find a suspicious process by the name ```runddl32.exe``` with a pid of ```300```

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20071504.png)

- The actual windows process is of the name ```rundl32.exe``` related to the execution of dynamic link libraries (DLLs) in Windows
- Dumping the process ```python vol.py -f bruh.raw -o ./output windows.dumpfile --pid 300``` and looking up the hash outputed by ```md5sum file.0x8e905f80.0x8f050f70.DataSectionObject.runddl32.exe.dat``` on VirusTotal we can confirm that the process is malicious

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20095657.png)

#### Q5. Identify another process associated with the aforementioned suspicious process. What makes this association unusual?

- We see that the notepad.exe file is started by the process runddl32.exe. This is unusual behaviour. In a normal scenario, "rundll32.exe" might be used to run a specific function within a DLL, but it's uncommon for it to directly launch "notepad.exe." This behavior could be an attempt to hide or disguise the malicious activity, making it look like a normal system process.

#### Q6. Provide the complete path, including the executable name, of the concealed program.

- This can be achieved by using the command ```python vol.py -f bruh.raw windows.filescan | grep "runddl32.exe" ```

- The filepath is found to be ```\Users\0XSH3R~1\AppData\Local\Temp\MSDCSC\runddl32.exe```

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20120609.png)

#### Q7. Determine the API leveraged by the malware to retrieve the status of a specified virtual key on the keyboard.

#### Q8. Investigate and disclose the Attacker's Command and Control (C2) domain name and port number in the format "domain name:port number."

- Running the command ```python vol.py -f bruh.raw windows.netscan ``` yields no useful results
```bash
──(apetun㉿kali)-[~/Desktop/volatility3-2.4.1/volatility3-2.4.1]
└─$ python vol.py -f bruh.raw windows.netscan                                    
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created

0x3dc24f50      UDPv4   0.0.0.0 0       *       0               1104    svchost.exe     2023-02-20 19:01:31.000000 
0x3dc24f50      UDPv6   ::      0       *       0               1104    svchost.exe     2023-02-20 19:01:31.000000 
0x3dc25738      TCPv4   0.0.0.0 5357    0.0.0.0 0       LISTENING       4       System  N/A
0x3dc25738      TCPv6   ::      5357    ::      0       LISTENING       4       System  N/A
0x3dc48950      UDPv4   0.0.0.0 5355    *       0               1104    svchost.exe     2023-02-20 19:01:34.000000 
0x3dc48950      UDPv6   ::      5355    *       0               1104    svchost.exe     2023-02-20 19:01:34.000000 
0x3dc91008      TCPv4   192.168.80.130  139     0.0.0.0 0       LISTENING       4       System  N/A
0x3dc942b0      UDPv4   192.168.80.130  137     *       0               4       System  2023-02-20 19:01:35.000000 
0x3dd225c8      UDPv4   0.0.0.0 60475   *       0               908     svchost.exe     2023-02-20 19:03:06.000000 
0x3dd4a858      UDPv4   0.0.0.0 3702    *       0               2576    svchost.exe     2023-02-20 19:03:06.000000 
0x3dd4a858      UDPv6   ::      3702    *       0               2576    svchost.exe     2023-02-20 19:03:06.000000 
0x3dd4ab50      UDPv4   0.0.0.0 64933   *       0               2576    svchost.exe     2023-02-20 19:01:33.000000 
0x3dd4be38      UDPv4   0.0.0.0 64934   *       0               2576    svchost.exe     2023-02-20 19:01:33.000000 
0x3dd4be38      UDPv6   ::      64934   *       0               2576    svchost.exe     2023-02-20 19:01:33.000000 
0x3dd77008      UDPv4   0.0.0.0 3702    *       0               2576    svchost.exe     2023-02-20 19:03:06.000000 
0x3dd77008      UDPv6   ::      3702    *       0               2576    svchost.exe     2023-02-20 19:03:06.000000 
0x3dd77190      UDPv4   0.0.0.0 64935   *       0               908     svchost.exe     2023-02-20 19:01:33.000000 
0x3dd77c80      UDPv4   0.0.0.0 3702    *       0               908     svchost.exe     2023-02-20 19:03:06.000000 
0x3dd78b60      UDPv4   0.0.0.0 64936   *       0               908     svchost.exe     2023-02-20 19:01:33.000000 
0x3dd78b60      UDPv6   ::      64936   *       0               908     svchost.exe     2023-02-20 19:01:33.000000 
0x3de0a398      UDPv4   0.0.0.0 5355    *       0               1104    svchost.exe     2023-02-20 19:01:34.000000 
0x3de2d610      TCPv4   0.0.0.0 49154   0.0.0.0 0       LISTENING       952     svchost.exe     N/A
0x3de30838      TCPv4   0.0.0.0 49154   0.0.0.0 0       LISTENING       952     svchost.exe     N/A
0x3de30838      TCPv6   ::      49154   ::      0       LISTENING       952     svchost.exe     N/A
0x3df73360      UDPv4   192.168.80.130  138     *       0               4       System  2023-02-20 19:01:35.000000 
0x3dfe07f0      TCPv4   0.0.0.0 49156   0.0.0.0 0       LISTENING       488     lsass.exe       N/A
0x3dfe07f0      TCPv6   ::      49156   ::      0       LISTENING       488     lsass.exe       N/A
0x3dfe0d80      TCPv4   0.0.0.0 49156   0.0.0.0 0       LISTENING       488     lsass.exe       N/A
0x3e06c930      UDPv4   0.0.0.0 3702    *       0               908     svchost.exe     2023-02-20 19:03:06.000000 
0x3e06c930      UDPv6   ::      3702    *       0               908     svchost.exe     2023-02-20 19:03:06.000000 
0x3e0f9438      TCPv4   0.0.0.0 49153   0.0.0.0 0       LISTENING       752     svchost.exe     N/A
0x3e0f9438      TCPv6   ::      49153   ::      0       LISTENING       752     svchost.exe     N/A
0x3e0f96e0      TCPv4   0.0.0.0 49153   0.0.0.0 0       LISTENING       752     svchost.exe     N/A
0x3e15c4b0      TCPv4   0.0.0.0 49152   0.0.0.0 0       LISTENING       404     wininit.exe     N/A
0x3e15c4b0      TCPv6   ::      49152   ::      0       LISTENING       404     wininit.exe     N/A
0x3e160008      TCPv4   0.0.0.0 135     0.0.0.0 0       LISTENING       700     svchost.exe     N/A
0x3e163ee8      TCPv4   0.0.0.0 135     0.0.0.0 0       LISTENING       700     svchost.exe     N/A
0x3e163ee8      TCPv6   ::      135     ::      0       LISTENING       700     svchost.exe     N/A
0x3e16b5d8      TCPv4   0.0.0.0 49152   0.0.0.0 0       LISTENING       404     wininit.exe     N/A
0x3ead3008      UDPv6   ::1     64930   *       0               2576    svchost.exe     2023-02-20 19:01:33.000000 
0x3ead61c0      UDPv6   fe80::98ff:dcd7:bafd:7ab        64929   *       0               2576    svchost.exe     2023-02-20 19:01:33.000000 
0x3ead7890      UDPv4   192.168.80.130  1900    *       0               2576    svchost.exe     2023-02-20 19:01:33.000000 
0x3ead7948      UDPv4   127.0.0.1       64932   *       0               2576    svchost.exe     2023-02-20 19:01:33.000000 
0x3ead7d98      UDPv4   192.168.80.130  64931   *       0               2576    svchost.exe     2023-02-20 19:01:33.000000 
0x3ead8838      UDPv6   fe80::98ff:dcd7:bafd:7ab        1900    *       0               2576    svchost.exe     2023-02-20 19:01:33.000000 
0x3eae2298      UDPv6   ::1     1900    *       0               2576    svchost.exe     2023-02-20 19:01:33.000000 
0x3eaf1c58      UDPv4   127.0.0.1       1900    *       0               2576    svchost.exe     2023-02-20 19:01:33.000000 
0x3eafb1b0      UDPv4   0.0.0.0 3702    *       0               2576    svchost.exe     2023-02-20 19:03:06.000000 
0x3f27eb70      TCPv4   0.0.0.0 445     0.0.0.0 0       LISTENING       4       System  N/A
0x3f27eb70      TCPv6   ::      445     ::      0       LISTENING       4       System  N/A
0x3f28bba8      TCPv4   0.0.0.0 49155   0.0.0.0 0       LISTENING       480     services.exe    N/A
0x3f28bba8      TCPv6   ::      49155   ::      0       LISTENING       480     services.exe    N/A
0x3f28bf58      TCPv4   0.0.0.0 49155   0.0.0.0 0       LISTENING       480     services.exe    N/A
0x3fc63658      UDPv4   0.0.0.0 60476   *       0               908     svchost.exe     2023-02-20 19:03:06.000000 
0x3fc63658      UDPv6   ::      60476   *       0               908     svchost.exe     2023-02-20 19:03:06.000000 
0x3fc864a8      UDPv4   0.0.0.0 3702    *       0               908     svchost.exe     2023-02-20 19:03:06.000000 
0x3fcc4280      UDPv4   0.0.0.0 3702    *       0               908     svchost.exe     2023-02-20 19:03:06.000000 
0x3fcc4280      UDPv6   ::      3702    *       0               908     svchost.exe     2023-02-20 19:03:06.000000 
0x3fcd8cb0      UDPv4   0.0.0.0 3702    *       0               2576    svchost.exe     2023-02-20 19:03:06.000000 

```
- Going back to VirusTotal under the Network section of Behavior section of the entry we can find the C2 as ```tcp://test213.no-ip.info:1604```

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20144453.png)

#### Q9. Indications suggest the presence of a keylogger. Can you locate the path of the keylogger executable?
- Searhing for ```"runddl32.exe""keylogger"``` on google yields a lot of results about a certain virus called "DarkComet"
- Reading up on it we discover a few things : 
   - DarkComet is a remote access trojan (RAT) developed by Jean-Pierre Lesueur (known as DarkCoderSc), an independent programmer and computer security coder from France.
   - The program was discontinued, partially due to its use in the Syrian civil war to monitor activists but also due to its author's fear of being arrested for unnamed reasons.
   - It offers numerous features which are explained in detail here : https://www.malwarebytes.com/blog/news/2012/06/you-dirty-rat-part-1-darkcomet
- The configuration settings for the malware can be found from the memory dump runddl32.exe process ```strings ./output/300.dmp > ./output/output.txt ```

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20153543.png)

- This is the explaination for each value in the configuration settings :
```bashMUTEX={DC_MUTEX-KHNEW06} # This is the Mutant/mutex value that is used

SID={Guest16} # Campaign name

FWB={0} # Firewall bypass (Windows Firewall)

NETDATA={test213.no-ip.info:1604} # C2 *Most seem to be 1604 so that is probably the default

GENCODE={F6FE8i2BxCpu} # Not quite sure on this one, perhaps part of building the encryption?

KEYNAME={MicroUpdate} # Registry key name

EDTDATE={16/04/2007} # Used for time stamp manipulation

PERSINST={1} # Persistence

MELT={0} # Delete the original executable or not

CHANGEDATE={1} # Use the EDTDATE to modify the $SI timestamps

DIRATTRIB={6} # Modify the attributes of a directory, such as make it hidden

FILEATTRIB={6} # Modify the attributes of a file, such as make it hidden

OFFLINEK={1} # Offline keylogging
```
- As we can see offline keylogging is set to 1 in the configuration so the  will continue to log keystroke to a local file that can then be picked up by the attacker as they want. When disabled, the attacker only has access to keystrokes when the attacker has a live session open with the victim. The logged files are saved as .dc files. The location of these files can be found out by running another filescan.
- We get the output as ```\Users\0xSh3rl0ck\AppData\Roaming\dclogs\2023-02-20-2.dc``` after running the command ```python vol.py -f bruh.raw windows.filescan | grep "\.dc"```

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20154619.png)

#### Q10. We suspect the malware is utilizing persistence techniques. Can you identify and describe the method employed?

- Definition : Persistence in cybersecurity occurs when a threat actor discreetly maintains long-term access to systems despite disruptions such as restarts or changed credentials. Bad actors can place an implant or a “stub” that both evades automated antivirus solutions and kickstarts more malware.
- DarkComet achieves persistence through modifying the Registry 

- #### Registry Key Persistence :
   ```
   Registry keys are the most popular and common malware persistence mechanism used by threat actors.
   The Windows registry is a database that stores configuration settings for the operating system and installed software.
   Malware can create or modify registry keys to run automatically when the system starts.
   This allows the malware to persist even after the system has been rebooted.
   Malware achieves persistence by modifying the registry keys in one of AutoStart Extention Points (ASEPs). Below are some of the registry keys that malware mostly achieves its persistence by editing the registry keys at the User Level:
   - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
   - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
   If the malware is able to gain admin privileges, it will infect some of the keys at admin/system-level privileges:
   - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
   - HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
   
   ```

#### Q11. Uncover the key name and its corresponding value within the context of this incident.

- The keyname can be found from the configs as ```KEYNAME={MicroUpdate}```
- The command ```python2 vol.py -f bruh.raw --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"``` can be used to get the complete info

![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20161031.png)

#### Q12. Identify the unconventional handle used by the malware.

- Handles related to the malware can be found using the command ```python2 vol.py -f bruh.raw --profile=Win7SP1x86_23418 handles -p 300```
- The output is verbose but the only interesting handle seems to be the mutant name being ```DC_MUTEX-KHNEW06```
   <details>
     <summary>
       Output
     </summary>
      
         ```
         Offset(V)     Pid     Handle     Access Type             Details
         ---------- ------ ---------- ---------- ---------------- -------
         99ddf7c8    300        0x4        0x3 Directory        KnownDlls
         0x84362038    300        0x8   0x100020 File             \Device\HarddiskVolume1\Users\0xSh3rl0ck\Desktop
         0x843b02c8    300        0xc   0x100020 File             \Device\HarddiskVolume1\Windows\winsxs\x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.7601.18837_none_ec86b8d6858ec0bc
         0x843adf80    300       0x10   0x100020 File             \Device\HarddiskVolume1\Windows\winsxs\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.7601.24203_none_5c030043a0118fbf
         0x843ac528    300       0x14   0x1f0001 ALPC Port        
         0x9c02bbb0    300       0x18    0x20019 Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\NLS\SORTING\VERSIONS
         0xa88b3248    300       0x1c        0x1 Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\SESSION MANAGER
         0x84396d18    300       0x20      0x804 EtwRegistration  
         0x843b0698    300       0x24  0x21f0003 Event            
         0x85ed4428    300       0x28    0xf037f WindowStation    WinSta0
         0x85e9e590    300       0x2c    0xf01ff Desktop          Default
         0x85ed4428    300       0x30    0xf037f WindowStation    WinSta0
         0x9c018288    300       0x34    0xf003f Key              MACHINE
         0x84396228    300       0x38      0x804 EtwRegistration  
         0x84396298    300       0x3c   0x1f0003 Event            
         0x843961e0    300       0x40   0x1f0003 Event            
         0x843961a0    300       0x44   0x1f0003 Event            
         0x84396460    300       0x48   0x1f0003 Event            
         0x84396420    300       0x4c   0x1f0003 Event            
         0x843963e0    300       0x50   0x1f0003 Event            
         0x87cf6780    300       0x54        0xf Directory        BaseNamedObjects
         0x843b0728    300       0x58   0x1f0001 Mutant           
         0x843b0b28    300       0x5c   0x1f0001 Mutant           
         0x843963a0    300       0x60   0x1f0003 Event            
         0x84396640    300       0x64      0x804 EtwRegistration  
         0x843965c8    300       0x68      0x804 EtwRegistration  
         0x84398718    300       0x6c      0x804 EtwRegistration  
         0x843986a0    300       0x70      0x804 EtwRegistration  
         0x84398628    300       0x74      0x804 EtwRegistration  
         0x843637c0    300       0x78      0x804 EtwRegistration  
         0x84363748    300       0x7c      0x804 EtwRegistration  
         0x843636d0    300       0x80      0x804 EtwRegistration  
         0x843968c0    300       0x84      0x804 EtwRegistration  
         0x84396848    300       0x88      0x804 EtwRegistration  
         0x843967d0    300       0x8c      0x804 EtwRegistration  
         0x843affc0    300       0x90      0x804 EtwRegistration  
         0x843aff48    300       0x94      0x804 EtwRegistration  
         0x843afe58    300       0x98      0x804 EtwRegistration  
         0x843afed0    300       0x9c      0x804 EtwRegistration  
         0x843afde0    300       0xa0      0x804 EtwRegistration  
         0x84396580    300       0xa4   0x1f0003 Event            
         0x843afd78    300       0xa8   0x100003 Semaphore        
         0x843ae8e0    300       0xac   0x100003 Semaphore        
         0x843c76b0    300       0xb0   0x100003 Semaphore        
         0x8438fdd0    300       0xb4   0x100003 Semaphore        
         0x8438fd88    300       0xb8   0x100003 Semaphore        
         0x8438fd40    300       0xbc   0x100003 Semaphore        
         0x8438fd00    300       0xc0   0x1f0003 Event            
         0x8438fcc0    300       0xc4   0x1f0003 Event            
         0x84398570    300       0xc8   0x120089 File             \Device\HarddiskVolume1\Windows\System32\en-US\msvfw32.dll.mui
         0x843af460    300       0xcc   0x120089 File             \Device\HarddiskVolume1\Windows\System32\en-US\avicap32.dll.mui
         0x9ca80fd0    300       0xd0    0xf003f Key              USER\S-1-5-21-4151118248-3926227922-3552599106-1000
         0x84368df8    300       0xd4      0x804 EtwRegistration  
         0x84368d80    300       0xd8      0x804 EtwRegistration  
         0x84368c48    300       0xdc   0x1f0001 ALPC Port        
         0x8fa4ddc8    300       0xe0        0x4 Section          
         0x84368c00    300       0xe4   0x1f0003 Event            
         0x8438f378    300       0xe8   0x1f0003 Event            
         0x8438f338    300       0xec   0x1f0003 Event            
         0x8438f1c8    300       0xf0      0x804 EtwRegistration  
         0x8438f240    300       0xf4      0x804 EtwRegistration  
         0x843c7038    300       0xf8   0x120089 File             \Device\HarddiskVolume1\Windows\System32\en-US\user32.dll.mui
         0x8438f2b0    300       0xfc   0x1f0003 Event            
         0x8436bd48    300      0x100   0x1fffff Thread           TID 3116 PID 300
         0x8436bd08    300      0x104   0x1f0003 Event            
         0x8436a030    300      0x108   0x1fffff Thread           TID 2144 PID 300
         0x87d3bfd0    300      0x10c    0xf003f Key              MACHINE\SYSTEM\CONTROLSET001\SERVICES\WINSOCK2\PARAMETERS\PROTOCOL_CATALOG9
         0x8438f0e8    300      0x110   0x1f0003 Event            
         0x9c018370    300      0x114    0xf003f Key              MACHINE\SYSTEM\CONTROLSET001\SERVICES\WINSOCK2\PARAMETERS\NAMESPACE_CATALOG5
         0x84398fa8    300      0x118   0x1f0003 Event            
         0x84398f68    300      0x11c   0x1f0003 Event            
         0x843c7700    300      0x120   0x100001 File             \Device\KsecDD
         0x8fa8f8d0    300      0x124       0x28 Token            
         0x84398f28    300      0x128   0x1f0003 Event            
         0x84398ee8    300      0x12c   0x1f0003 Event            
         0x84398ea8    300      0x130   0x1f0003 Event            
         0x84398dc0    300      0x134      0x804 EtwRegistration  
         0x84398e38    300      0x138      0x804 EtwRegistration  
         0x84398d78    300      0x13c   0x1f0003 Event            
         0x8436a030    300      0x140   0x1fffff Thread           TID 2144 PID 300
         0x8db306a8    300      0x144   0x16019f File             \Device\Afd\Endpoint
         0x862c5a40    300      0x148   0x1f0003 IoCompletion     
         0x85e257a0    300      0x14c    0xf00ff TpWorkerFactory  
         0xa7cd9d00    300      0x150    0xf0003 KeyedEvent       
         0x86132d98    300      0x154   0x100002 Timer            
         0x85e25100    300      0x158   0x1f0003 Timer            
         0x843af688    300      0x15c   0x1fffff Thread           TID 3112 PID 300
         0x843af688    300      0x160   0x1fffff Thread           TID 3112 PID 300
         0x8b6ece00    300      0x164   0x1f0003 IoCompletion     
         0x85e258e0    300      0x168    0xf00ff TpWorkerFactory  
         0x843c71a0    300      0x16c  0x21f0003 Event            
         0x842eb8b8    300      0x170   0x1f0001 Mutant           DC_MUTEX-KHNEW06
         0x85e25598    300      0x174   0x100002 Timer            
         0x843ad600    300      0x178   0x1fffff Thread           TID 2544 PID 300
         0x843ad030    300      0x17c   0x1fffff Thread           TID 100 PID 300
         0x9c028458    300      0x180    0xf003f Key              USER\S-1-5-21-4151118248-3926227922-3552599106-1000\SOFTWARE
         0x8aaff6c8    300      0x184        0x6 Section          windows_shell_global_counters
         0x9c0284b8    300      0x188    0x20019 Key              MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\FOLDERDESCRIPTIONS\{905E63B6-C1BF-494E-B29C-65B732D3D21A}\PROPERTYBAG
         0x843ad318    300      0x18c   0x1fffff Thread           TID 2740 PID 2556
         0x84390030    300      0x190   0x1fffff Process          notepad.exe(2556)
         0x84390380    300      0x194   0x1fffff Thread           TID 3008 PID 300
         0x84390690    300      0x198   0x1fffff Thread           TID 3004 PID 2556
         0x9c02a818    300      0x19c        0x8 Key              USER\S-1-5-21-4151118248-3926227922-3552599106-1000\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION
         0x9c02d180    300      0x1a0        0x8 Key              MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\APPCOMPATFLAGS
         0xa7d89258    300      0x1a4        0x9 Key              MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\IMAGE FILE EXECUTION OPTIONS
         0x843e5198    300      0x1a8  0x21f0003 Event            
         0x843c9030    300      0x1ac   0x1fffff Thread           TID 200 PID 300
         0x843e5218    300      0x1b0   0x1f0003 Event            
         0x9c0294d8    300      0x1b4        0x1 Key              USER\S-1-5-21-4151118248-3926227922-3552599106-1000\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER
         0x843e51d8    300      0x1b8   0x1f0003 Event            
         0x843e6748    300      0x1bc   0x100020 File             \Device\HarddiskVolume1\Windows\winsxs\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.18837_none_41e855142bd5705d
         0x843c74d8    300      0x1c0      0x804 EtwRegistration  
         0x843ac1e8    300      0x1c4      0x804 EtwRegistration  
         0x9c02adb0    300      0x1c8    0xf003f Key              MACHINE\SOFTWARE\CLASSES
         0xa887fc50    300      0x1cc    0xf003f Key              USER\S-1-5-21-4151118248-3926227922-3552599106-1000_CLASSES
         0x886d6948    300      0x1d0        0x4 Section          __ComCatalogCache__
         0x841ac310    300      0x1d4   0x100001 Event            MaximumCommitCondition
         0x886d6948    300      0x1d8        0x4 Section          __ComCatalogCache__
         0x843b0400    300      0x1dc      0x804 EtwRegistration  
         0xa7d06030    300      0x1e0    0x20003 Directory        
         0xa7cffb38    300      0x1e4        0x4 Section          ASqmManifestVersion
         0x843e6d90    300      0x1e8   0x120089 File             \Device\HarddiskVolume1\Windows\Registration\R000000000006.clb
         0x9c01b860    300      0x1ec    0xf0005 Section          
         0x84384aa0    300      0x1f0      0x804 EtwRegistration  
         0x84384a28    300      0x1f4      0x804 EtwRegistration  
         0x9caa63f0    300      0x1f8        0x6 Section          windows_shell_global_counters
         0x9c0283f8    300      0x1fc    0x20019 Key              MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\FOLDERDESCRIPTIONS\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PROPERTYBAG
         0x84384920    300      0x200      0x804 EtwRegistration  
         0x843e5310    300      0x204   0x1f0003 Event            
         0x843848d0    300      0x208   0x100003 Semaphore        
         0x84384888    300      0x20c   0x100003 Semaphore        
         0x84384840    300      0x210   0x100003 Semaphore        
         0x843847f8    300      0x214   0x100003 Semaphore        
         0x843847b0    300      0x218   0x100003 Semaphore        
         0x84384768    300      0x21c   0x100003 Semaphore        
         0x843c9a58    300      0x220   0x100003 Semaphore        
         0x843c9a10    300      0x224   0x100003 Semaphore        
         0x843e70c8    300      0x228      0x804 EtwRegistration  
         0x84262630    300      0x22c      0x804 EtwRegistration  
         0x843e4528    300      0x230   0x1f0003 Event            
         0x843ac810    300      0x234   0x1f0001 Mutant           
         0x843e4620    300      0x238   0x1f0003 Event            
         0x843ac7c0    300      0x23c   0x1f0001 Mutant           
         0x843a5500    300      0x240   0x16019f File             \Device\Afd\Endpoint
         0x860db9b8    300      0x244   0x16019f File             \Device\Afd\Endpoint
         0x85f7ae88    300      0x248   0x1f0001 ALPC Port        
         0x843c9030    300      0x24c   0x1fffff Thread           TID 200 PID 300
         0x843e6ce8    300      0x250   0x1f0003 Event            
         0x84363300    300      0x254  0x21f0003 Event            
         0x84396d90    300      0x258      0x804 EtwRegistration  
         0x843e6038    300      0x25c   0x16019f File             \Device\Afd\Endpoint
         0x841e6b58    300      0x260      0x804 EtwRegistration  
         0x85ba92c8    300      0x264      0x804 EtwRegistration  
         0x861cc660    300      0x268      0x804 EtwRegistration  
         0x843e66a0    300      0x26c   0x1f0003 Event            
         0x843c9030    300      0x270   0x1fffff Thread           TID 200 PID 300
         0x863569e0    300      0x274   0x16019f File             \Device\Afd\Endpoint
         0x843e4870    300      0x278   0x1f0003 Event            
         0x843e4968    300      0x27c   0x1f0003 Event            
         0x843c9350    300      0x280   0x1f0003 Event            
         0x965fffc0    300      0x284      0x804 EtwRegistration  
         0x965fff48    300      0x288      0x804 EtwRegistration  
         0x85456320    300      0x28c      0x804 EtwRegistration  
         0x854562a8    300      0x290      0x804 EtwRegistration  
         0x84297488    300      0x294      0x804 EtwRegistration  
         0x84297410    300      0x298      0x804 EtwRegistration  
         0x84259fc0    300      0x29c      0x804 EtwRegistration  
         0x84259f48    300      0x2a0      0x804 EtwRegistration  
         0x84270a70    300      0x2a4      0x804 EtwRegistration  
         0x842709f8    300      0x2a8      0x804 EtwRegistration  
         0x84259628    300      0x2ac      0x804 EtwRegistration  
         0x842595b0    300      0x2b0      0x804 EtwRegistration  
         0x8427e328    300      0x2b4      0x804 EtwRegistration  
         0x8427e2b0    300      0x2b8      0x804 EtwRegistration  
         0x84262ea8    300      0x2bc      0x804 EtwRegistration  
         0x843af970    300      0x2c0   0x1f0003 Event            
         0x843b0090    300      0x2c4   0x1f0003 Event            
         0x84262e30    300      0x2c8      0x804 EtwRegistration  
         0x841f6a00    300      0x2cc      0x804 EtwRegistration  
         0x843b0ae8    300      0x2d0   0x1f0003 Event            
         0x843e4d90    300      0x2d4   0x1f0001 ALPC Port        
         0x843e5548    300      0x2d8   0x100080 File             \Device\Nsi
         0x86319c40    300      0x2dc  0x21f0003 Event            
         0x9546bef0    300      0x2e0   0x16019f File             \Device\Afd\Endpoint
         0x97a458b0    300      0x2e4   0x16019f File             \Device\Afd\Endpoint
         0x923cdc88    300      0x2e8   0x16019f File             \Device\Afd\Endpoint
         0x8551d9d8    300      0x2ec   0x16019f File             \Device\Afd\Endpoint
         0x85f91f80    300      0x2f0   0x16019f File             \Device\Afd\Endpoint
         0x952fe9b0    300      0x2f4   0x16019f File             \Device\Afd\Endpoint
         0x8cdfe140    300      0x2f8   0x16019f File             \Device\Afd\Endpoint
         0x862a72f0    300      0x2fc   0x16019f File             \Device\Afd\Endpoint
         0x861dd678    300      0x300   0x16019f File             \Device\Afd\Endpoint
         0x85f92560    300      0x304   0x16019f File             \Device\Afd\Endpoint
         0x843981f0    300      0x308   0x16019f File             \Device\Afd\Endpoint
         0x84396938    300      0x30c   0x16019f File             \Device\Afd\Endpoint
         0x8613ee60    300      0x310   0x16019f File             \Device\Afd\Endpoint
         0x860496d8    300      0x314   0x16019f File             \Device\Afd\Endpoint
         0x858da7d0    300      0x318   0x16019f File             \Device\Afd\Endpoint
         0x86091178    300      0x31c   0x16019f File             \Device\Afd\Endpoint
         0x84bb0f80    300      0x320   0x16019f File             \Device\Afd\Endpoint
         0x863aaf80    300      0x324   0x16019f File             \Device\Afd\Endpoint
         0x84baf538    300      0x328   0x16019f File             \Device\Afd\Endpoint
         0x8f8001c0    300      0x32c   0x16019f File             \Device\Afd\Endpoint
         0x8630eb78    300      0x330   0x16019f File             \Device\Afd\Endpoint
         0x843e5640    300      0x334   0x16019f File             \Device\Afd\Endpoint
         0x843e5738    300      0x338   0x16019f File             \Device\Afd\Endpoint
         0x843e5a20    300      0x33c   0x16019f File             \Device\Afd\Endpoint
         0x843e5b18    300      0x340   0x16019f File             \Device\Afd\Endpoint
         0x843e5c10    300      0x344   0x16019f File             \Device\Afd\Endpoint
         0x843e5f40    300      0x348   0x16019f File             \Device\Afd\Endpoint
         0x843e4380    300      0x34c   0x16019f File             \Device\Afd\Endpoint
         0x843e4478    300      0x350   0x16019f File             \Device\Afd\Endpoint
         0x843e4570    300      0x354   0x16019f File             \Device\Afd\Endpoint
         0x843e4668    300      0x358   0x16019f File             \Device\Afd\Endpoint
         0x843e47c0    300      0x35c   0x16019f File             \Device\Afd\Endpoint
         0x843e48b8    300      0x360   0x16019f File             \Device\Afd\Endpoint
         0x843e49b0    300      0x364   0x16019f File             \Device\Afd\Endpoint
         0x843e4cb8    300      0x368   0x16019f File             \Device\Afd\Endpoint
         0x843e4ec8    300      0x36c   0x16019f File             \Device\Afd\Endpoint
         0x843e4f80    300      0x370   0x16019f File             \Device\Afd\Endpoint
         0x843af560    300      0x374   0x16019f File             \Device\Afd\Endpoint
         0x843e7d00    300      0x378   0x16019f File             \Device\Afd\Endpoint
         0x843e7f80    300      0x37c   0x16019f File             \Device\Afd\Endpoint
         0x843e6900    300      0x380   0x16019f File             \Device\Afd\Endpoint
         0x843e6ab8    300      0x384   0x16019f File             \Device\Afd\Endpoint
         0x843e6c38    300      0x388   0x16019f File             \Device\Afd\Endpoint
         0x843e4aa8    300      0x38c   0x16019f File             \Device\Afd\Endpoint
         0x843e7ae0    300      0x390   0x16019f File             \Device\Afd\Endpoint
         0x843e4208    300      0x394   0x16019f File             \Device\Afd\Endpoint
         0x850062f8    300      0x398   0x16019f File             \Device\Afd\Endpoint
         0x842803f8    300      0x39c   0x16019f File             \Device\Afd\Endpoint
         0x93fff6f8    300      0x3a0   0x16019f File             \Device\Afd\Endpoint
         0x84386268    300      0x3a4   0x16019f File             \Device\Afd\Endpoint
         0x861c1b30    300      0x3a8   0x16019f File             \Device\Afd\Endpoint
         0x861501c0    300      0x3ac   0x16019f File             \Device\Afd\Endpoint
         0x843f6368    300      0x3b0   0x16019f File             \Device\Afd\Endpoint
         0x84322200    300      0x3b4   0x16019f File             \Device\Afd\Endpoint
         0x85f715c8    300      0x3b8   0x16019f File             \Device\Afd\Endpoint
         0x860c5d60    300      0x3bc   0x16019f File             \Device\Afd\Endpoint
         0x85402038    300      0x3c0   0x16019f File             \Device\Afd
         0x842d6c08    300      0x3c4   0x16019f File             \Device\Afd\Endpoint
         0x8430c278    300      0x3c8   0x16019f File             \Device\Afd\Endpoint
         0x84366288    300      0x3cc   0x16019f File             \Device\Afd\Endpoint
         0x843f6978    300      0x3d0   0x16019f File             \Device\Afd\Endpoint
         0x843ac978    300      0x3d4   0x16019f File             \Device\Afd\Endpoint
         0x8434adb8    300      0x3d8   0x16019f File             \Device\Afd\Endpoint
         0x843ac710    300      0x3dc   0x16019f File             \Device\Afd\Endpoint
         0x8430d3e0    300      0x3e0   0x16019f File             \Device\Afd\Endpoint
         0x8430d328    300      0x3e4   0x16019f File             \Device\Afd\Endpoint
         0x84367698    300      0x3e8   0x16019f File             \Device\Afd\Endpoint
         0x843672a8    300      0x3ec   0x16019f File             \Device\Afd\Endpoint
         0x84369950    300      0x3f0   0x16019f File             \Device\Afd\Endpoint
         0x84369398    300      0x3f4   0x16019f File             \Device\Afd\Endpoint
         0x843692e0    300      0x3f8   0x16019f File             \Device\Afd\Endpoint
         0x86238980    300      0x3fc   0x16019f File             \Device\Afd\Endpoint
         0x860ccd60    300      0x400   0x16019f File             \Device\Afd\Endpoint
         0x84369228    300      0x404   0x16019f File             \Device\Afd\Endpoint
         0x842fa3e0    300      0x408   0x16019f File             \Device\Afd\Endpoint
         0x8637a300    300      0x40c   0x16019f File             \Device\Afd\Endpoint
         0x842b3f80    300      0x410   0x16019f File             \Device\Afd\Endpoint
         0x860a3418    300      0x414   0x16019f File             \Device\Afd\Endpoint
         0x862d7bf8    300      0x418   0x16019f File             \Device\Afd\Endpoint
         0x8425c818    300      0x41c   0x16019f File             \Device\Afd\Endpoint
         0x841e7b80    300      0x420   0x16019f File             \Device\Afd\Endpoint
         0x843589d0    300      0x424   0x16019f File             \Device\Afd\Endpoint
         0x84358918    300      0x428   0x16019f File             \Device\Afd\Endpoint
         0x842f0580    300      0x42c   0x16019f File             \Device\Afd\Endpoint
         0x84349f80    300      0x430   0x16019f File             \Device\Afd\Endpoint
         0x843499c8    300      0x434   0x16019f File             \Device\Afd\Endpoint
         0x862a8038    300      0x438   0x16019f File             \Device\Afd\Endpoint
         0x855323e8    300      0x43c   0x16019f File             \Device\Afd\Endpoint
         0x842cb318    300      0x440   0x16019f File             \Device\Afd\Endpoint
         0x84278488    300      0x444   0x16019f File             \Device\Afd\Endpoint
         0x863f4330    300      0x448   0x16019f File             \Device\Afd\Endpoint
         0x863f4a60    300      0x44c   0x16019f File             \Device\Afd\Endpoint
         0x863f18f8    300      0x450   0x16019f File             \Device\Afd\Endpoint
         0x863f93a8    300      0x454   0x16019f File             \Device\Afd\Endpoint
         0x863f2c28    300      0x458   0x16019f File             \Device\Afd\Endpoint
         0x841d45d0    300      0x45c   0x16019f File             \Device\Afd\Endpoint
         0x862fa500    300      0x460   0x16019f File             \Device\Afd\Endpoint
         0x85402458    300      0x464   0x16019f File             \Device\Afd\Endpoint
         0x863ef450    300      0x468   0x16019f File             \Device\Afd\Endpoint
         0x8427b528    300      0x46c   0x16019f File             \Device\Afd\Endpoint
         0x84a02dc8    300      0x470   0x16019f File             \Device\Afd\Endpoint
         0x841e9038    300      0x474   0x16019f File             \Device\Afd\Endpoint
         0x84356940    300      0x478   0x16019f File             \Device\Afd\Endpoint
         0x841e9f80    300      0x47c   0x16019f File             \Device\Afd\Endpoint
         0x86131640    300      0x480   0x16019f File             \Device\Afd\Endpoint
         0x853ff518    300      0x484   0x16019f File             \Device\Afd\Endpoint
         0x85bad268    300      0x488   0x16019f File             \Device\Afd\Endpoint
         0x85baa378    300      0x48c   0x16019f File             \Device\Afd\Endpoint
         0x863f3be8    300      0x490   0x16019f File             \Device\Afd\Endpoint
         0x8434bd58    300      0x494   0x16019f File             \Device\Afd\Endpoint
         0x90546c70    300      0x498   0x16019f File             \Device\Afd\Endpoint
         0x86130258    300      0x49c   0x16019f File             \Device\Afd\Endpoint
         0x86130698    300      0x4a0   0x16019f File             \Device\Afd\Endpoint
         0x84356a00    300      0x4a4   0x16019f File             \Device\Afd\Endpoint
         0x86046038    300      0x4a8   0x16019f File             \Device\Afd\Endpoint
         0x8431eb98    300      0x4ac   0x16019f File             \Device\Afd\Endpoint
         0x8431ea28    300      0x4b0   0x16019f File             \Device\Afd\Endpoint
         0x84a02d10    300      0x4b4   0x16019f File             \Device\Afd\Endpoint
         0x8430dec8    300      0x4b8   0x16019f File             \Device\Afd\Endpoint
         0x863f00d8    300      0x4bc   0x16019f File             \Device\Afd\Endpoint
         0x86168d98    300      0x4c0   0x16019f File             \Device\Afd\Endpoint
         0x85532ac0    300      0x4c4   0x16019f File             \Device\Afd\Endpoint
         0x85532e58    300      0x4c8   0x16019f File             \Device\Afd\Endpoint
         0x842de7f0    300      0x4cc   0x16019f File             \Device\Afd\Endpoint
         0x85e25038    300      0x4d0   0x16019f File             \Device\Afd\Endpoint
         0x93f8e270    300      0x4d4   0x16019f File             \Device\Afd\Endpoint
         0x863efd18    300      0x4d8   0x16019f File             \Device\Afd\Endpoint
         0x86141b48    300      0x4dc   0x16019f File             \Device\Afd\Endpoint
         0x842da038    300      0x4e0   0x16019f File             \Device\Afd\Endpoint
         0x85e24388    300      0x4e4   0x16019f File             \Device\Afd\Endpoint
         0x855df510    300      0x4e8   0x16019f File             \Device\Afd\Endpoint
         0x8438d8a0    300      0x4ec   0x16019f File             \Device\Afd\Endpoint
         0x863ef960    300      0x4f0   0x16019f File             \Device\Afd\Endpoint
         0x841e9898    300      0x4f4   0x16019f File             \Device\Afd\Endpoint
         0x8434bf80    300      0x4f8   0x16019f File             \Device\Afd\Endpoint
         0x8434dd60    300      0x4fc   0x16019f File             \Device\Afd\Endpoint
         0x90546390    300      0x500   0x16019f File             \Device\Afd\Endpoint
         0x86130a40    300      0x504   0x16019f File             \Device\Afd\Endpoint
         0x841e9950    300      0x508   0x16019f File             \Device\Afd\Endpoint
         0x863f4420    300      0x50c   0x16019f File             \Device\Afd\Endpoint
         0x842fd210    300      0x510   0x16019f File             \Device\Afd\Endpoint
         0x84397500    300      0x514   0x16019f File             \Device\Afd\Endpoint
         0x8612f038    300      0x518   0x16019f File             \Device\Afd\Endpoint
         0x86299180    300      0x51c   0x16019f File             \Device\Afd\Endpoint
         0x842a6758    300      0x520   0x16019f File             \Device\Afd\Endpoint
         0x842a6458    300      0x524   0x16019f File             \Device\Afd\Endpoint
         0x863536f0    300      0x528   0x16019f File             \Device\Afd\Endpoint
         0x8434d210    300      0x52c   0x16019f File             \Device\Afd\Endpoint
         0x8437e8f8    300      0x530   0x16019f File             \Device\Afd\Endpoint
         0x8437d2a0    300      0x534   0x16019f File             \Device\Afd\Endpoint
         0x8437b2a0    300      0x538   0x16019f File             \Device\Afd\Endpoint
         0x860c0278    300      0x53c   0x16019f File             \Device\Afd\Endpoint
         0x8438b300    300      0x540   0x16019f File             \Device\Afd\Endpoint
         0x8435b280    300      0x544   0x16019f File             \Device\Afd\Endpoint
         0x8634e038    300      0x548   0x16019f File             \Device\Afd\Endpoint
         0x841f6be0    300      0x54c   0x16019f File             \Device\Afd\Endpoint
         0x841f7c48    300      0x550   0x16019f File             \Device\Afd\Endpoint
         0x85f7a9e8    300      0x554   0x16019f File             \Device\Afd\Endpoint
         0x84259910    300      0x558   0x16019f File             \Device\Afd\Endpoint
         0x84288800    300      0x55c   0x16019f File             \Device\Afd\Endpoint
         0x841f4530    300      0x560   0x16019f File             \Device\Afd\Endpoint
         0x843823c8    300      0x564   0x16019f File             \Device\Afd\Endpoint
         0x841f3940    300      0x568   0x16019f File             \Device\Afd\Endpoint
         0x842b1aa0    300      0x56c   0x16019f File             \Device\Afd\Endpoint
         0x86071408    300      0x570   0x16019f File             \Device\Afd\Endpoint
         0x862b6a68    300      0x574   0x16019f File             \Device\Afd\Endpoint
         0x842f7d50    300      0x578   0x16019f File             \Device\Afd\Endpoint
         0x86178a20    300      0x57c   0x16019f File             \Device\Afd\Endpoint
         0x8436a450    300      0x580   0x16019f File             \Device\Afd\Endpoint
         0x84287438    300      0x584   0x16019f File             \Device\Afd\Endpoint
         0x84279d60    300      0x588   0x16019f File             \Device\Afd\Endpoint
         0x84289a68    300      0x58c   0x16019f File             \Device\Afd\Endpoint
         0x842e2a78    300      0x590   0x16019f File             \Device\Afd\Endpoint
         0x842799b0    300      0x594   0x16019f File             \Device\Afd\Endpoint
         0x842eab98    300      0x598   0x16019f File             \Device\Afd\Endpoint
         0x842b6780    300      0x59c   0x16019f File             \Device\Afd\Endpoint
         0x84304190    300      0x5a0   0x16019f File             \Device\Afd\Endpoint
         0x842eadb8    300      0x5a4   0x16019f File             \Device\Afd\Endpoint
         0x843045b8    300      0x5a8   0x16019f File             \Device\Afd\Endpoint
         0x842f53a0    300      0x5ac   0x16019f File             \Device\Afd\Endpoint
         0x841e75a8    300      0x5b0   0x16019f File             \Device\Afd\Endpoint
         0x842f58d0    300      0x5b4   0x16019f File             \Device\Afd\Endpoint
         0x84305a60    300      0x5b8   0x16019f File             \Device\Afd\Endpoint
         0x843935f8    300      0x5bc   0x16019f File             \Device\Afd\Endpoint
         0x84389b48    300      0x5c0   0x16019f File             \Device\Afd\Endpoint
         0x85e25c70    300      0x5c4   0x16019f File             \Device\Afd\Endpoint
         0x842c02d0    300      0x5c8   0x16019f File             \Device\Afd\Endpoint
         0x842bb880    300      0x5cc   0x16019f File             \Device\Afd\Endpoint
         0x842d5a68    300      0x5d0   0x16019f File             \Device\Afd\Endpoint
         0x842f4c98    300      0x5d4   0x16019f File             \Device\Afd\Endpoint
         0x8425a268    300      0x5d8   0x16019f File             \Device\Afd\Endpoint
         0x85d4b490    300      0x5dc   0x16019f File             \Device\Afd\Endpoint
         0x8604b278    300      0x5e0   0x16019f File             \Device\Afd\Endpoint
         0x85efcd60    300      0x5e4   0x16019f File             \Device\Afd\Endpoint
         0x84299458    300      0x5e8   0x16019f File             \Device\Afd\Endpoint
         0x842dd360    300      0x5ec   0x16019f File             \Device\Afd\Endpoint
         0x842f4590    300      0x5f0   0x16019f File             \Device\Afd\Endpoint
         0x85f9bcd8    300      0x5f4   0x16019f File             \Device\Afd\Endpoint
         0x862d7ac0    300      0x5f8   0x16019f File             \Device\Afd\Endpoint
         0x85ff7038    300      0x5fc   0x16019f File             \Device\Afd\Endpoint
         0x84399298    300      0x600   0x16019f File             \Device\Afd\Endpoint
         0x842d7038    300      0x604   0x16019f File             \Device\Afd\Endpoint
         0x843a3890    300      0x608   0x16019f File             \Device\Afd\Endpoint
         0x842b7700    300      0x60c   0x16019f File             \Device\Afd\Endpoint
         0x843957a0    300      0x610   0x16019f File             \Device\Afd\Endpoint
         0x843393d0    300      0x614   0x16019f File             \Device\Afd\Endpoint
         0x85dfd398    300      0x618   0x16019f File             \Device\Afd\Endpoint
         0x860a2de8    300      0x61c   0x16019f File             \Device\Afd\Endpoint
         0x842b79d8    300      0x620   0x16019f File             \Device\Afd\Endpoint
         0x843a7228    300      0x624   0x16019f File             \Device\Afd\Endpoint
         0x843a7170    300      0x628   0x16019f File             \Device\Afd\Endpoint
         0x843a3038    300      0x62c   0x16019f File             \Device\Afd\Endpoint
         0x843a3cf0    300      0x630   0x16019f File             \Device\Afd\Endpoint
         0x843a3b80    300      0x634   0x16019f File             \Device\Afd\Endpoint
         0x843a3ac8    300      0x638   0x16019f File             \Device\Afd\Endpoint
         0x843a3a10    300      0x63c   0x16019f File             \Device\Afd\Endpoint
         0x84299c68    300      0x640   0x16019f File             \Device\Afd\Endpoint
         0x842fd400    300      0x644   0x16019f File             \Device\Afd\Endpoint
         0x842fd4b8    300      0x648   0x16019f File             \Device\Afd\Endpoint
         0x842f33d0    300      0x64c   0x16019f File             \Device\Afd\Endpoint
         0x843a9440    300      0x650   0x16019f File             \Device\Afd\Endpoint
         0x843ab620    300      0x654   0x16019f File             \Device\Afd\Endpoint
         0x84338668    300      0x658   0x16019f File             \Device\Afd\Endpoint
         0x843a4200    300      0x65c   0x16019f File             \Device\Afd\Endpoint
         0x843b86f0    300      0x660   0x16019f File             \Device\Afd\Endpoint
         0x843bd388    300      0x664   0x16019f File             \Device\Afd\Endpoint
         0x84387900    300      0x668   0x16019f File             \Device\Afd\Endpoint
         0x843bfa90    300      0x66c   0x16019f File             \Device\Afd\Endpoint
         0x843a6a78    300      0x670   0x16019f File             \Device\Afd\Endpoint
         0x8438a4d8    300      0x674   0x16019f File             \Device\Afd\Endpoint
         0x861c3850    300      0x678   0x16019f File             \Device\Afd\Endpoint
         0x843a9270    300      0x67c   0x16019f File             \Device\Afd\Endpoint
         0x843876d0    300      0x680   0x16019f File             \Device\Afd\Endpoint
         0x843a4920    300      0x684   0x16019f File             \Device\Afd\Endpoint
         0x843ca1f8    300      0x688   0x16019f File             \Device\Afd\Endpoint
         0x842eccc8    300      0x68c   0x16019f File             \Device\Afd\Endpoint
         0x843c1408    300      0x690   0x16019f File             \Device\Afd
         0x8426d758    300      0x694   0x16019f File             \Device\Afd\Endpoint
         0x84391360    300      0x698   0x16019f File             \Device\Afd\Endpoint
         0x843a5f80    300      0x69c   0x16019f File             \Device\Afd\Endpoint
         0x843bdf80    300      0x6a0   0x16019f File             \Device\Afd\Endpoint
         0x84336b30    300      0x6a4   0x16019f File             \Device\Afd\Endpoint
         0x843786f8    300      0x6a8   0x16019f File             \Device\Afd\Endpoint
         0x842ad110    300      0x6ac   0x16019f File             \Device\Afd\Endpoint
         0x843bb7f0    300      0x6b0   0x16019f File             \Device\Afd\Endpoint
         0x85f79868    300      0x6b4   0x16019f File             \Device\Afd\Endpoint
         0x843d5a58    300      0x6b8   0x16019f File             \Device\Afd\Endpoint
         0x84328d60    300      0x6bc   0x16019f File             \Device\Afd\Endpoint
         0x84a15380    300      0x6c0   0x16019f File             \Device\Afd\Endpoint
         0x843c4858    300      0x6c4   0x16019f File             \Device\Afd\Endpoint
         0x84378d60    300      0x6c8   0x16019f File             \Device\Afd\Endpoint
         0x843c2d60    300      0x6cc   0x16019f File             \Device\Afd\Endpoint
         0x843a49f0    300      0x6d0   0x16019f File             \Device\Afd\Endpoint
         0x84328440    300      0x6d4   0x16019f File             \Device\Afd\Endpoint
         0x842afa58    300      0x6d8   0x16019f File             \Device\Afd\Endpoint
         0x842af1c8    300      0x6dc   0x16019f File             \Device\Afd\Endpoint
         0x84387038    300      0x6e0   0x16019f File             \Device\Afd\Endpoint
         0x843c6308    300      0x6e4   0x16019f File             \Device\Afd\Endpoint
         0x8630bde0    300      0x6e8   0x16019f File             \Device\Afd\Endpoint
         0x86252880    300      0x6ec   0x16019f File             \Device\Afd\Endpoint
         0x98558580    300      0x6f0   0x16019f File             \Device\Afd\Endpoint
         0x974cb970    300      0x6f4   0x16019f File             \Device\Afd\Endpoint
         0x843c6a30    300      0x6f8   0x16019f File             \Device\Afd\Endpoint
         0x843c6c50    300      0x6fc   0x16019f File             \Device\Afd\Endpoint
         0x84380560    300      0x700   0x16019f File             \Device\Afd\Endpoint
         0x843c24d0    300      0x704   0x16019f File             \Device\Afd\Endpoint
         0x86355038    300      0x708   0x16019f File             \Device\Afd\Endpoint
         0x8634f688    300      0x70c   0x16019f File             \Device\Afd\Endpoint
         0x8634e6f8    300      0x710   0x16019f File             \Device\Afd\Endpoint
         0x8635b838    300      0x714   0x16019f File             \Device\Afd\Endpoint
         0x843caca8    300      0x718   0x16019f File             \Device\Afd\Endpoint
         0x84370ae0    300      0x71c   0x16019f File             \Device\Afd\Endpoint
         0x843da890    300      0x720   0x16019f File             \Device\Afd\Endpoint
         0x843d1760    300      0x724   0x16019f File             \Device\Afd\Endpoint
         ```
   </details>

#### Q13. Assist in determining the family classification of this malware.

- We can find the family of the virus by submitting the SHA-256 string of ```de760a609a43e93318cc43ba353ed81361961324fc730dd4638e49a5fb022560``` from VirusTotal at https://www.talosintelligence.com/ which is ```DarkKomet```
![alt text](https://github.com/Apetun/Cryptonite/blob/main/Writeups/Forensics/bruh.raw/Screenshot%202024-01-19%20164738.png)


