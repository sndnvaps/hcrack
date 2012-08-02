#include "md5c.c"
#include "hmac-md5.c"
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
//
//
//	This is free software
//
//

char *usage = "hcrack 0.1: a hmac-md5 cracker written in C\n\n"
			  "Usage: hcrack [-t threads] [-h hash] [-k key] [-w wordlist]\n"
			  "-h hash,			hmac hash to crack\n"
			  "-k key,				hmac key that goes with hash\n"
			  "-t threads,			number of threads to use concurrently. Default: 1\n"
			  "-w wordlist,			wordlist mode, follow with path to wordlist, one word per line\n" 
			  "-b [a] [a1] [all],		(optional)character set for bruteforce: a = alphabet,\n"
			  "				a1 = alphanumerical, all = all ascii characters  Default: a1\n\n";

char *key;
char *hash;
char *wl;
int want_stop = 0;
int numThreads;
char *alnum = "abcdefghijklmnopqrstuvwxyz0123456789";
char *alpha = "abcdefghijklmnopqrstuvwxyz";
char *all = "abcdefghujklmnopqrstuvwxyz0123456789!@#$%^&*()-=_+[]{}\\|{};:'\"/?.>,<";
char *charset;

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
struct thread_args {
	int pw_len;
	char *keyspace;
};
void *hmac_brute(void *args)  // thanks to redlizard for help with this one.
{
	struct thread_args *arguments = args;
	int pw_len = arguments->pw_len; 
	char *keyspace = arguments->keyspace;
	int keyspace_len = strlen(keyspace);
	int state[pw_len];

	int i;

	for(i=0;i<pw_len;i++)
	{
		state[i] = 0;
	}

	while(!want_stop)
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
			printf("Password: %s\n", text);
			want_stop = 1;
			break;
		}

		int index = 0;
		while(index<pw_len && ++state[index] == keyspace_len)
		{
			state[index++] = 0;
		}
		if(index == pw_len)
		{
			break;
		}
	}
	pthread_exit(NULL);
}


int main(int argc, char** argv)
{
	if(argc <= 1)
	{
		fprintf(stderr, usage);
		exit(EXIT_FAILURE);
	}
	int opt;
	numThreads = 1;
	charset = alnum;
	while((opt = getopt(argc, argv, "k:h:w:t:b:")) != -1)
	{
		switch(opt)
		{	
			case 'b':
				if(strcmp(optarg, "a") == 0)	
				{
					charset = alpha;
					break;
				} else 
				if(strcmp(optarg, "a1") == 0)
				{
					charset = alnum;
					break;
				} else
				if(strcmp(optarg, "all") == 0)
				{
					charset = all;
					break;
				} else {
					printf("invalid character set specified!\n");
					fprintf(stderr, usage);
					exit(EXIT_FAILURE);
				}
			case 't':
				numThreads = atoi(optarg);
				break;
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
		int i = 0;
		int q = 0;
		pthread_t threads[numThreads-1];
		while(!want_stop)
		{
			for(i=0;i<numThreads;i++)
			{
				struct thread_args args;
				args.pw_len = i+q;
				args.keyspace = charset;
				pthread_create(&threads[i], NULL, hmac_brute, (void *)&args);
			}
			for(i=0;i<numThreads;i++)
			{
				pthread_join(threads[i], NULL);
			}
			q += numThreads;
		}
	}
}
				
