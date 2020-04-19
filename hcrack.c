#include "md5c.c"
#include "hmac-md5.c"
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

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
char *all = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-=_+[]{}\\|{};:'\"/?.>,<";
char *charset;
unsigned char target_digest[16];

int compare_digest(unsigned char d1[], unsigned char d2[])
{
	int i;
	if(sizeof(d1) != sizeof(d2))
	{
		return 0;
	}
	for(i=0;i<sizeof(d1);i++)
	{
		if(d1[i] != d2[i])
		{
			return 0;
		}
	}
	return 1;
}
void string_to_digest(const char hexstring[])
{
	const char *pos = hexstring;
	size_t count = 0;
	for(count=0;count<sizeof(target_digest)/sizeof(target_digest[0]); count++)
	{
		sscanf(pos, "%2hhx", &target_digest[count]);
		pos += 2 * sizeof(char);
	}
}
	
void hmac_wordlist(char *wl_path)
{
	FILE *wordlist;
	char buffer[256];
	unsigned char digest[16];
	int key_len = strlen(key);
	wordlist = fopen(wl_path, "r");
	while(!feof(wordlist))
	{
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
		hmac_md5(buffer, text_len, key, key_len, digest);
		if(compare_digest(target_digest, digest))
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
	char guess[pw_len + 1];
	unsigned char digest[16];
	int key_len = strlen(key);

	int i;

	for(i=0;i<pw_len;i++)
	{
		state[i] = 0;
	}
	state[0] = upper_limit;
	while(!want_stop)
	{
		for(i=0;i<pw_len;i++)
		{
			guess[i] = keyspace[state[i]];
			if(state[0] == lower_limit)
			{
				pthread_exit(NULL);
			}
		}
		guess[pw_len] = '\0';
		unsigned char *text = guess;
		int text_len = strlen(text);
		hmac_md5(text, text_len, key, key_len, digest);
		if(compare_digest(target_digest, digest))
		{
			printf("Password: %s\n", text);
			want_stop = 1;
			break;
		}
	
		int index = pw_len-1;
		while(++state[index] == keyspace_len)
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
	string_to_digest(hash);
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
			printf("cracking %d characters...\n", len);
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
					args[i].lower_limit = ((chars_per_thread*(1+i))+offset);
				}
				pthread_create(&threads[i], NULL, hmac_brute, (void *)&args[i]);
				last_limit = (args[i].lower_limit);
			}
			for(i=0;i<num_threads;i++)
			{
				pthread_join(threads[i], NULL);
			}
			len++;
		}
	}
}
				
