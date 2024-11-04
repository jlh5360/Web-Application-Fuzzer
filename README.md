
# Web Application Fuzzer

## Setup and Installation

To set up the environment for the fuzzer, ensure you have the following packages installed:

### Prerequisites

* Python 3.x
  * Strongly recommend Python3+ due to some inconsistencies in the 2.7 versions of packages (i.e. use "python3" and "pip3" to run [since Python 2 is long dead](https://www.python.org/doc/sunset-python-2/)).
* Install the necessary libraries:
  * [Requests](http://docs.python-requests.org/en/latest/)  |  [Mechanical Soup](https://github.com/MechanicalSoup/MechanicalSoup)  |  [argparse](https://docs.python.org/3/library/argparse.html)  |  [Beautiful Soup](https://pypi.org/project/beautifulsoup4/)
  * **Commands:**
    * `pip3 install requests`
    * `pip3 install mechanicalsoup`
    * `pip3 install argparse`
    * `pip3 install beautifulsoup4`
  * **NOTE:**	If you tried to run the program and get an error like this below:
    *ModuleNotFoundError: No module named 'mechanicalsoup'*
    Simply run this command to resolve the issue:  `python3 -m pip install mechanicalsoup`

## Python Script Execution Examples

`python3 .\fuzz.py discover http://127.0.0.1/dvwa/ --custom-auth=dvwa --common-words=mywords.txt`

`python3 .\fuzz.py discover https://www.rit.edu/ --common-words=mywords.txt`

## Command-Line Interaction

**Manpage:**

```txt
  fuzz [discover | test] url OPTIONS

  COMMANDS:
    discover  Output a comprehensive, human-readable list of all discovered inputs to the system. Techniques include both crawling and guessing.
    test      Discover all inputs, then attempt a list of exploit vectors on those inputs. Report anomalies that could be vulnerabilities.

  OPTIONS:
    Options can be given in any order.

    --custom-auth=string     Signal that the fuzzer should use hard-coded authentication for a specific application (e.g. dvwa).

    Discover options:
      --common-words=file    Newline-delimited file of common words to be used in page guessing. Required.
      --extensions=file      Newline-delimited file of path extensions, e.g. ".php". Optional. Defaults to ".php" and the empty string if not specified

    Test options:
      --common-words=file    Same option as in discover - see above.
      --extensions=file      Same option as in discover - see above.
      --vectors=file         Newline-delimited file of common exploits to vulnerabilities. Required.
      --sanitized-chars=file Newline-delimited file of characters that should be sanitized from inputs. Defaults to just < and >
      --sensitive=file       Newline-delimited file data that should never be leaked. It's assumed that this data is in the application's database (e.g. test data), but is not reported in any response. Required.
      --slow=500             Number of milliseconds considered when a response is considered "slow". Optional. Default is 500 milliseconds
```

**Example invocations:**

```txt
  # Discover inputs, default extensions, no login
  fuzz discover http://localhost:8080 --common-words=mywords.txt

  # Discover inputs to DVWA using our hard-coded authentication, port 8080
  fuzz discover http://localhost:8080 --custom-auth=dvwa --extensions=extensions.txt --common-words=mywords.txt

  # Discover and Test DVWA, port 8000, default extensions: sanitized characters, extensions and slow threshold
  fuzz test http://localhost:8000 --custom-auth=dvwa --common-words=words.txt --vectors=vectors.txt --sensitive=creditcards.txt
```
