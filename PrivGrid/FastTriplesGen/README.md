# FastTriplesGen

## Function

This project implements the generation of multiplicative triples.

## Compile

Install dependencies:

```bash
sudo apt update
sudo apt install build-essential cmake make git libgmp-dev -y
```

Clone source code:

```bash
git clone https://github.com/Alice-lei/PrivGrid.git
cd PrivGrid/FastTriplesGen
```

Compile:

```bash
mkdir build && cd build
cmake .. && make
```

You can find the executable file in the `bin` directory.

## Usage
```
FastTriplesGen [Options] <Destination>

Options  Destination
-r       (required) Role, input integer 1 or 2. 1 means server, 2 means client.
-i       (optional) IP Address. Default 127.0.0.1
-p       (optional) Port Number. Default 26481
-h       Help
```

## Author

Qingyun Qiu, a master student from Xidian University. 

Code Languages: C++ and Java.

Research interests: Secure Multi-Party Computation

E-mail Address: qiuqingyun98@outlook.com  

Github page: https://github.com/qiuqingyun.
