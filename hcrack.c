#include "md5c.c"
#include "hmac-md5.c"
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#define LIMIT_UNLIMITED 10000
//
//
//	This is free software
//
//

char *usage = "hcrack 0.1: a hmac-md5 cracker written in C\n\n"
			  "Usage: hcrack [-t threads] [-h hash] [-k key] [-w wordlist]\n"
			  "-t threads,			number of threads to use.  Set this to your processors' core count.\n"
			  "-h hash,			hmac hash to crack\n"
			  "-k key,				hmac key that goes with hash\n"
			  "-w wordlist,			wordlist mode, follow with path to wordlist, one word per line\n" 
			  "-b [a] [a1] [all],		(optional)character set for bruteforce: a = alphabet,\n"
			  "				a1 = alphanumerical, all = all ascii characters  Default: a1\n\n";

char *key;
char *hash;
char *wl;
int want_stop = 0;
int num_threads;
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
	char *keyspace;
	int pw_len;
	int upper_limit;
	int lower_limit;
};

void *hmac_brute(void *args)  // thanks to redlizard for help with this 
{
	struct thread_args *arguments = args;
	char *keyspace = arguments->keyspace;
	int pw_len = arguments->pw_len;
	int upper_limit = arguments->upper_limit;
	int lower_limit = arguments->lower_limit;

	int keyspace_len = strlen(keyspace);
	int state[pw_len];

	int i;
	for(i=0;i<pw_len;i++)
	{
		state[i] = 0;
	}
	state[0] = upper_limit;
	while(!want_stop)
	{
		char guess[pw_len + 1];
		for(i=0;i<pw_len;i++)
		{
			//printf("%d\n", state[0]);
			guess[i] = keyspace[state[i]];
			if(state[0] == lower_limit)
			{
				pthread_exit(NULL);
			}
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

		int index = pw_len-1;
		while(index<pw_len && ++state[index] == keyspace_len)
		{
			state[index--] = 0;
		}
		if(index == -1)
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
	charset = alnum;
	num_threads = 1;
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
				num_threads = atoi(optarg);
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
		int i;
		int len = 1;
		pthread_t threads[num_threads];
		struct thread_args args[num_threads];
		while(!want_stop)
		{
			for(i=0;i<num_threads;i++)
			{
				args[i].keyspace = charset;
				args[i].pw_len = len;
			}
			int last_limit=0;
			int offset = 0;
			int chars_per_thread = strlen(charset)/num_threads;
			int remainder = strlen(charset) % num_threads;
			if(remainder)
			{
				offset = remainder;
			}
			for(i=0;i<num_threads;i++)
			{
				args[i].upper_limit = last_limit;
				if(i==num_threads-1)
				{
					args[i].lower_limit = LIMIT_UNLIMITED;
				} else {
					args[i].lower_limit = ((chars_per_thread*(1+i))+offset)-1;
				}
				pthread_create(&threads[i], NULL, hmac_brute, (void *)&args[i]);
				last_limit = (args[i].lower_limit+1);
			}
			for(i=0;i<num_threads;i++)
			{
				pthread_join(threads[i], NULL);
	
			}
			len++;
		}
	}
}
				
