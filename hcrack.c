#include "md5c.c"
#include "hmac-md5.c"
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
//
//
//	This is free software
//
//

char *usage = "hcrack 0.1: a hmac-md5 cracker written in C\n\n"
			  "Usage: hcrack [-h hash] [-k key] [-w wordlist]\n"
			  "-h hash,			hmac hash to crack\n"
			  "-k key,				hmac key that goes with hash\n"
			  "-w				wordlist mode, follow with path to wordlist, one word per line\n\n"; 

char *key;
char *hash;
char *wl;
int want_stop = 0;
char *alnum = "abcdefghijklmnopqrstuvwxyz0123456789";
char *alpha = "abcdefghijklmnopqrstuvwxyz";

void hmac_wordlist(char *wl_path)
{
	FILE *wordlist;
	wordlist = fopen(wl_path, "r");
	while(!feof(wordlist))
	{
		char buffer[256];
		unsigned char digest[16];
		fgets(buffer, sizeof buffer, wordlist);
		char *newline = strchr(buffer,'\n');
		if(newline)
		{
			*newline = '\0';
		}
		char *returnchar = strchr(buffer,'\r');
		if(returnchar)
		{
			*returnchar = '\0';
		}
		int text_len = strlen(buffer);
		int key_len = strlen(key);
		hmac_md5(buffer, text_len, key, key_len, digest);
		char result[33];
		sprintf(result, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
		if(strcmp(result, hash) == 0)
		{
			printf("Password: %s\n", buffer);
			return;
		}
	}
}

void hmac_brute(char *keyspace, int pw_len)  // thanks to redlizard for help with this one.
{
	int keyspace_len = strlen(keyspace);
	int state[pw_len];

	int i;

	for(i=0;i<pw_len;i++)
	{
		state[i] = 0;
	}

	while(1)
	{
		char guess[pw_len + 1];
		for(i=0;i<pw_len;i++)
		{
			guess[i] = keyspace[state[i]];
		}
		guess[pw_len] = '\0';
		unsigned char digest[16];
		unsigned char *text = guess;
		int text_len = strlen(text);
		int key_len = strlen(key);
		hmac_md5(text, text_len, key, key_len, digest);
		char result[33];
		sprintf(result, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
		if(strcmp(hash, result) == 0)
		{
			want_stop = 1;
			printf("Password: %s\n", text);
			return;
		}

		int index = 0;
		while(index<pw_len && ++state[index] == keyspace_len)
		{
			state[index++] = 0;
		}
		if(index == pw_len)
		{
			return;
		}
	}
}


int main(int argc, char** argv)
{
	if(argc <= 1)
	{
		fprintf(stderr, usage);
		exit(EXIT_FAILURE);
	}
	int opt;
	while((opt = getopt(argc, argv, "k:h:w:")) != -1)
	{
		switch(opt)
		{	
			case 'k':
				key = optarg;
				break;
			case 'h':
				hash = optarg;
				break;
			case 'w':
				wl = optarg;	
				break;
			case '?':
				fprintf(stderr, usage);
				exit(EXIT_FAILURE);
		}
	}
	if(!hash)
	{
		fprintf(stderr, "You didn't specify a hmac_md5 hash!\n");
		exit(EXIT_FAILURE);
	}
	if(!key)
	{
		fprintf(stderr, "You didn't specify a hmac_md5 key!\n");
		exit(EXIT_FAILURE);
	}
	if(wl)
	{
		hmac_wordlist(wl);
	} else {
		printf("Attempting to bruteforce!  This will take a while...\n");
		int i = 1;
		while(!want_stop)
		{
			printf("Cracking %d characters...\n", i);
			hmac_brute(alnum, i);
			i++;
		}
	}
}
				
