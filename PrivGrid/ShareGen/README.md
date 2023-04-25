# ShareGen

## Function

This project implements the generation of secure share.

## Compile

Install dependencies:

```bash
sudo apt update
sudo apt install build-essential cmake make git libgmp-dev -y
```

Clone source code:

```bash
git clone https://github.com/Alice-lei/Priv_.git
cd Priv_/PrivGrid/ShareGen
```

Compile:

```bash
mkdir build && cd build
cmake .. && make
```

You can find the executable file in the `bin` directory.

## Usage
```
ShareGen  [Options] <Destination>

Options    Destination
-s         (Required) Path to the directory where the data files are stored (*.csv)
-h         Help
```

## Author

Qingyun Qiu, a master student from Xidian University. 

Code Languages: C++ and Java.

Research interests: Secure Multi-Party Computation

E-mail Address: qiuqingyun98@outlook.com  

Github page: https://github.com/qiuqingyun.
