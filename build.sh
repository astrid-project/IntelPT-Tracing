#!/bin/bash
#build tracer
g++ -I./xed/include -c -o bin/tracer.o tracer.cpp
g++ -c -o bin/load_elf.o load_elf.c
#link tracer
g++ -g -o bin/tracer bin/load_elf.o bin/tracer.o -ldl libipt/libipt.a libxed/libxed.a
#build targets
gcc targets/t0.c -O0 -o bin/t0
gcc targets/t1.c -O0 -o bin/t1
gcc targets/t2.c -O0 -o bin/t2
gcc targets/t3.c -O0 -o bin/t3
gcc targets/t4.c -O0 -o bin/t4
gcc targets/t5.c -O0 -o bin/t5
gcc targets/t6.c -O0 -o bin/t6
gcc targets/t7.c -O0 -o bin/t7
gcc targets/t8.c -O0 -o bin/t8
#cleanup .o files
rm bin/*.o
