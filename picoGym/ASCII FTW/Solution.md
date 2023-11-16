# ASCII FTW

#### Solution

- Examining the file we see it is a ELF 64-bit LSB executable

- Changing permission and running the file we get
  
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/ASCII%20FTW/Screenshot%202023-11-16%20184110.png)

- Opening the file in ```ghidra``` 

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/ASCII%20FTW/Screenshot%202023-11-16%20183319.png)

- Following the ```_start``` keyword we find the main function
  
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/ASCII%20FTW/Screenshot%202023-11-16%20183539.png)

- Following the ```main``` function we find a few hex values followed by a printf statement
  
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/ASCII%20FTW/Screenshot%202023-11-16%20183729.png)

- Converting the hex values to ASCII we get the flag

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/ASCII%20FTW/Screenshot%202023-11-16%20183959.png)