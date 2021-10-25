# Solutions to Cryptography I programming exercises
Dan Boneh from Stanford University has an excellent online course on cryptography, hosted on Coursera, called Cryptography I. Each week of the course has a corresponding optional programming assignment. This repo contains solutions to all six of them. They are written in modern, statically type annotated, python 3.

## Usage
Requires python version `3.9` or newer. Install dependencies via:
```bash
python3 -m pip install -r requirements.txt
```

Run each solution by simply invoking the python interpreter:
```bash
python3 src/week$N.py
```

Verify static type checking of each solution via:
```bash
python3 -m pip install -U mypy # install mypy
mypy src/week$N.py
```
