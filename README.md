# Phishing Catcher

Catch possible phishing domains in near real time by looking for suspicious TLS certificate issuances reported to the [Certificate Transparency Log (CTL)](https://www.certificate-transparency.org/) via the [CertStream](https://certstream.calidog.io/) API. "Suspicious" issuances are those whose domain name scores beyond a certain threshold based on a configuration file.

This is just a working PoC. Feel free to contribute and tweak the code to fit your needs. 👍

![Screencast of example usage.](https://i.imgur.com/4BGuXkR.gif)

> ### Due to the large number of domains identified by Phishing_catcher, it is important to preserve the confidentiality of the information gathered.
>
> #### The results must be analysed in detail in order to extract suspect domains and rule out false positives.
>
> #### This programme is dedicated to the research for indicators and must not be abused.


### Installation

The script should work fine using Python2 or Python3. In either case, install the requirements after cloning or downloading the source code:

```sh
cd  # It is essential to clone the repository in its current user directory (/home/$USER) for the rest of the run, including log rotation.
git clone https://github.com/x0rz/phishing_catcher.git
sudo apt install python3.11-venv tmux -y

# Run in tmux session
tmux new -s phishing_catcher
cd phishing_catcher/
python3 -m venv venv_phishing_catcher
source venv_phishing_catcher/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
# To run in VSCode for example, add the path (/home/$USER/<PATH>/phishing_catcher/venv_phishing_catcher/lib/python3.11/site-packages) in the pylance parameters (Settings/Extensions/Pylance : Python > Analysis : Extra Paths)

# Run the script from the phishing_catcher directory so that the log_rotate() function applies correctly. The final directories for this function will be stored in /home/$USER
# If this is not the case, adjust the constants in catch_phishing.py and log_rotate.py
# Please note that the directory in which the log files are created is the parent of the directory in which the repository is located and from which the script is run. 
# Make sure that you have write access to this directory, or change the access path to
python3 catch_phishing.py
ctrl B => d # Detach from the tmux session
tmux a -t phishing_catcher # Attach the phishing_catcher session

deactivate  # When you want to leave virtual environment

# kill tmux session
tmux ls # List of sessions
tmux kill-session -t phishing_catcher
```

### Configuration

Phishing Catcher uses a simple YAML configuration file to assign a numeric score for strings that can be found in a TLS certificate's common name or SAN field (i.e., a cert's domain name). The configuration file, [`suspicious.yaml`](suspicious.yaml), ships with sensible defaults, but you can adjust or add to both the strings it contains and the score assigned to each string by editing an override file, [`external.yaml`](external.yaml).

Both the default `suspicious.yaml` and the user-modifiable `external.yaml` configuration files contain two YAML dictionaries: `keywords` and `tlds`. The keys of the dictionaries are the strings and the values are the scores to assign if that string is found in the domain name for an issued certificate. For example:

```yaml
keywords:
    'login': 25
```

Here, a score of `25` is added to the generic keyword `login` when it is found in a TLS certificate domain name. Increasing this value will raise the level of suspicion against domains with the string `login` in them, thus allowing you to subject these certificate issuances to increased scrutiny.

However, in order to be reported as suspicious by Phishing Catcher, the score assigned to a given certificate must meet or exceed (`>=`, "greater than or equal to") the following thresholds:

| Score | Reported as  |
| -----:| ------------ |
|    60 | `Potential`  |
|    70 | `Likely`     |
|    80 | `Suspicious` |
|    90 | `Problematic` |

> :bulb: See the `score_domain()` function in the source code for details regarding the scoring algorithm.

### Usage

Once configured to your liking, usage is as simple as running the script:

```
$ ./catch_phishing.py
```

### Example phishing caught

![Paypal Phishing](https://i.imgur.com/AK60EYz.png)

### Phishing catcher in Docker container

If you running MacOs or having a different OS version that would make the installation of phishing_catcher difficult, then having the tool dockerized is one of your options.

```
docker build . -t phishing_catcher
```
![container](https://i.imgur.com/nEo13PH.jpg)

# License

GNU GPLv3

If this tool has been useful for you, feel free to thank me by buying me a coffee.

[![Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoff.ee/x0rz)

# Improvements

- Ajust `issuers_list.txt` and `suspicious.yaml`
- Adjust the results to determine whether the certificate is potentially an OV or EV certificate (ie. `extensions` => certificatePolicies and `subject` => ‘O’ and ‘CN’)
- Push results (CSV files) into a dedicated repository
> *A results analysis programme is currently being developed to extract suspect domains and eliminate as many false positives as possible.*