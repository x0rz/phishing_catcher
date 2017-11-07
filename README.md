# Phishing catcher

Catching malicious phishing domain names using [certstream](https://certstream.calidog.io/) SSL certificates live stream.

This is just a working PoC, feel free to contribute and tweak the code to fit your needs 👍

![usage](https://i.imgur.com/4BGuXkR.gif)

### Installation

The script should work fine using Python2 or Python3.

You will need the following python packages installed: tqdm, certstream, entropy

```sh
pip install -r requirements.txt
```


### Usage

```
$ ./catch_phishing.py
```

### Example phishing caught

![Paypal Phishing](https://i.imgur.com/AK60EYz.png)

License
----
GNU GPLv3
