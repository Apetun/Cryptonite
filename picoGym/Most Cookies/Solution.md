#Most Cookies
####Flask
Flask is a lightweight, web development framework built using python language. Generally, for building websites we use HTML, CSS and JavaScript but in flask the python scripting language is used for developing the web-applications.
####What are Cookies?
Technically, cookies track user activity to save user information in the browser as key-value pairs, which can then be accessed whenever necessary by the developers to make a website easier to use. These enhances the personal user experience on a particular website by remembering your logins, your preferences and much more. 
####Solution
- Flask cookies are encoded using a secret key
- The secret key is used to generate a signature for each cookie that is sent to the browser
- The browser can then send back the cookie and the server can verify the signature
- If the signature is valid, the server can trust that the cookie was not modified by the client
- Looking at the server.py file, we can see the the secret key is a random choice  of the list given below 
  ```python
  cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]
  app.secret_key = random.choice(cookie_names)
    ```
- Inspecting the source of the webpage we can see the cookie for our current session is  ```eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9.ZUHZXA.Xu93eosN2C_t6xBIPf1Y2cScyrk```
![](https://github.com/Apetun/CryptoniteSTP/blob/main/picoGym/Most%20Cookies/Webpage.png)
- Using this:https://pypi.org/project/flask-unsign/ tool to decprypt the cookie 