# PcapPoisoning
#### Solution
- Opening the trace.pcap file in wireshark
  
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/PcapPoisoning/Screenshot%202023-11-09%20215021.png)

- Following the TCP stream we get the following output
  
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/PcapPoisoning/Screenshot%202023-11-09%20215046.png)

- The second stream has the flag
  
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/PcapPoisoning/Screenshot%202023-11-09%20215112.png)

- Alternatively we can run the strings command on the file and grep for picoCTF

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/PcapPoisoning/Screenshot%202023-11-09%20214944.png)