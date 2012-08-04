all:
	gcc -funroll-loops -pthread -pipe -fomit-frame-pointer -O3 -march=native -o hcrack hcrack.c
