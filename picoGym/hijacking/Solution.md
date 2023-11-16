# hijacking
#### Solution
- SSHing into the server and running the ```ls -a``` command we see a few hidden files including a .server.py file
- Opening the file we see the following code

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/hijacking/Screenshot%202023-11-16%20205632.png)

- Checking allowed commands using ```sudo -l``` we see that we can run the ```.server.py``` without a password

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/hijacking/Screenshot%202023-11-16%20211144.png)

- Running the ```.server.py``` file we get an error as output
- If we are able to change the code of the imported ```base64``` module we can get the flag
- Trying to find the location of the ```base64``` module 

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/hijacking/Screenshot%202023-11-16%20210043.png)

- We see that the ```base64``` module is located in ```/usr/lib/python3.8/base64.py```
- Opening it using ```vim``` we see the following code

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/hijacking/Screenshot%202023-11-16%20210459.png)

- Adding this code at the beginning of the file 

```python
import os
os.system('ls -al /root > /home/picoctf/r.txt')
```
- Looking through the ```r.txt``` file we see a file called ```.flag.txt```
- Adding ```os.system('cat /root/.flag.txt')``` to base64.py we get the flag

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/hijacking/Screenshot%202023-11-16%20210917.png)

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/hijacking/Screenshot%202023-11-16%20211331.png)