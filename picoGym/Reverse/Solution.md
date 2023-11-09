# Reverse
#### Solution
- Running ```file``` command on the file we get that its a 64-bit ELF file
  
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/Reverse/Screenshot%202023-11-09%20104113.png)

- Adding the executable permission
  
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/Reverse/Screenshot%202023-11-09%20124525.png)

- Running the file we get the following output we are prompted for a password doing an objdump on the read only section of the file we get the following flag
  
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/Reverse/Screenshot%202023-11-09%20124638.png)
