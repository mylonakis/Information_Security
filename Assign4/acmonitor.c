#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/md5.h>


struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};

void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}
/*
	My logic
*/

void bubbleSort_result(int *a, int *b, int max)
{
	// Sort by User's ID
	for(int i=0; i<max-1; i++)
	{
		for(int j=0; j<(max-(i+1)); j++)
		{
			if(a[j+1] < a[j])
			{
				int temp = a[j];
				a[j] = a[j+1];
				a[j+1] = temp;

				temp = b[j];
				b[j] = b[j+1];
				b[j+1] = temp;			
			}
		}
	}
}

void printTable_sorted(int *a, int *b, char *msg, int max, int atleast)
{
	bubbleSort_result(a, b, max);

	printf("|----------------------------------------------|\n");	
	printf("|   User's ID\t| %s |\n", msg);
	printf("|---------------|------------------------------|\n");

	for(int i=0; i<max; i++)
	{
		if(b[i]>=atleast)
		{
			printf("|      %d\t|\t\t%d\t", a[i], b[i]);
			printf("       |\n");
			printf("|---------------|------------------------------|\n");
		}
	}
}

void  list_unauthorized_accesses(FILE *log)
{
	int *list_users  = (int *)malloc(sizeof(int));
	int *list_counts = (int *)malloc(sizeof(int));

	int tokenID;
	int tokenDen;
	char *token;
	char *delim = " ";

	char *line=NULL;
	size_t len_line = 0;

	int i=0;
	while(1)
	{		
		size_t check = getline(&line, &len_line, log);
		if(check==-1)		
			break;

		//User's ID.
		token = strtok(line, delim);
		tokenID = atoi(token);

		//File's Path/Name.
		token = strtok(NULL, delim);

		//Log in Date.
		token = strtok(NULL, delim);

		//Log in Time.
		token = strtok(NULL, delim);

		//Access Type.
		token = strtok(NULL, delim);

		//Is Denied.
		token = strtok(NULL, delim);
		tokenDen = atoi(token);

		if(tokenDen == 1)
		{
			if(i == 0)
			{	
				i++;
				list_users = (int *)realloc(list_users, sizeof(int)*i);
				list_counts = (int *)realloc(list_counts, sizeof(int)*i);

				list_users[i-1] = tokenID;
				list_counts[i-1] = 0;
			}
			//Check if user exists int list_counts.
			int j=0;
			while(j<=i)
			{
				if(j == i)
				{	
					i++;
					list_users = (int *)realloc(list_users, sizeof(int)*i);
					list_counts = (int *)realloc(list_counts, sizeof(int)*i);

					list_users[j] = tokenID;
					list_counts[j] = 1;
					break;
				}

				if(list_users[j] == tokenID)
				{
					list_counts[j]++;
					break;
				}

				j++;
			}			
		}
	}
	char msg[30] = "Accesses without Permissions";
	printTable_sorted(list_users, list_counts, msg, i, 0);	
}


void list_file_modifications(FILE *log, char *file_to_scan)
{
	int user;
	int count=0;

	int tokenID;
	int tokenDen;
	int tokenAccess;
	char *token;
	char *delim = " ";
	char *tokenFile = NULL;

	unsigned char *pre_finger = (unsigned char *) malloc(MD5_DIGEST_LENGTH);
	unsigned char *cur_finger = (unsigned char *) malloc(MD5_DIGEST_LENGTH);

	char *line=NULL;
	size_t len_line = 0;

	int i=0;
	while(1)
	{		
		size_t check = getline(&line, &len_line, log);
		if(check==-1)		
			break;

		//User's ID.
		token = strtok(line, delim);
		tokenID = atoi(token);

		//File's Path/Name.
		token = strtok(NULL, delim);
		tokenFile = (char *)realloc(tokenFile, sizeof(char )*strlen(token));
		strcpy(tokenFile, token);

		//Log in Date.
		token = strtok(NULL, delim);

		//Log in Time.
		token = strtok(NULL, delim);

		//Access Type.
		token = strtok(NULL, delim);
		tokenAccess = atoi(token);

		//Is Denied.
		token = strtok(NULL, delim);
		tokenDen = atoi(token);

		//FingerPrint.
		token = strtok(NULL, delim);
		strcpy(cur_finger, (unsigned char*)token);

		if(i=0)
		{
			
			strcpy(pre_finger, cur_finger);
			i=-1;
		}

		if(strcmp(tokenFile, file_to_scan) == 0)
		{
			bool must = ((strcmp(cur_finger, pre_finger) != 0) && (tokenDen == 0) && (tokenAccess == 2));
			if(must)
			{	
				user = tokenID;
				count++;
			}

			strcpy(pre_finger, cur_finger);
		}

		//free(tokenFile);
	}


	char msg[40] = "\t\b\b\bChanges of fingerprint\t\b\b";
	printf("|----------------------------------------------|\n");	
	printf("|   User's ID\t| %s |\n", msg);
	printf("|---------------|------------------------------|\n");
	
	if(count==0)
	{
		char *noUser = "NaN";
		printf("|      %s\t|\t\t%d\t", noUser, count);
	}else		
		printf("|      %d\t|\t\t%d\t", user, count);

	printf("       |\n");
	printf("|---------------|------------------------------|\n");
		
	
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
