#!/bin/bash

astyle --style=linux --lineend=linux --max-code-length=78 --pad-oper ./*.h ./*.c
gcc main.c -pedantic -std=c99 -Werror -Wall -Wextra -O3 -mtune=native -march=native
