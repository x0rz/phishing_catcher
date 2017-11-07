# Phishing catcher

Catching phishing using [certstream](https://certstream.calidog.io/) SSL certificates live stream.

This is just a working PoC, feel free to contribute and tweak the code to fit your needs 👍

![usage](blob:https://imgur.com/7d4b67f7-642c-4ffb-a60a-4dda190bf7f6)

### Installation

Python v3 is required

You will need the following python packages installed: tqdm, certstream, entropy

```sh
pip3 install -r requirements.txt
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