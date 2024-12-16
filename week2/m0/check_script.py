# run sage lab2m1.py   in the command line 100 times

import sys
import os

def check_script():
    for _ in range(100):
        os.system("sage lab2m0.py")

if __name__ == "__main__":
    check_script()