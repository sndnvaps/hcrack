all:
	gcc -pthread -pipe -fomit-frame-pointer -O2 -march=native -o hcrack hcrack.c
