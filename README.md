# Solutions to Cryptography I programming exercises
Dan Boneh from Stanford University has an excellent online course on cryptography, hosted on [Coursera](https://www.coursera.org/learn/crypto), called **Cryptography I**. Each week of the course has a corresponding optional programming assignment.

This repo contains solutions to all six programming assignments. They are written in modern, statically type annotated, Python 3.

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
python3 -m pip install -U mypy
mypy src/*.py
```
