# File Types

#### Solution
- Running ```file``` command on the file we get it is an excecutable file
- Running ```sh``` command on the file we get
  
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/File%20Types/Screenshot%202023-11-04%20000807.png)
- After a bit of research we find out the file is a shell archive file installing the ```sharutils``` package we can extract the file
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/File%20Types/Screenshot%202023-11-04%20000854.png)
- Running the ```sh``` command now
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/File%20Types/Screenshot%202023-11-04%20000948.png)
- Running the ```file``` command on the extracted file we get an ```ar``` file
- Running ```binwalk``` twice on the file we get a ```lzip``` file
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/File%20Types/Screenshot%202023-11-04%20003734.png)
- Running ```lunzip``` on the file we get a ```LZ4``` file
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/File%20Types/Screenshot%202023-11-04%20003755.png)
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/File%20Types/Screenshot%202023-11-04%20003819.png)
- This pattern continues for a while with different file compression types
- After a while we get an encoded hex file which when decoded gives us the flag
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/File%20Types/Screenshot%202023-11-04%20003838.png)
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/File%20Types/Screenshot%202023-11-04%20003859.png)
![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/File%20Types/Screenshot%202023-11-04%20003926.png)
