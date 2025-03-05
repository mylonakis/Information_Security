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
		   "-m. Prints malicious users\n"
		   "-i <filename>. Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-v <number of files>. Prints the total number of files created in the last 20 minutes"
		   "-e. Prints all the files that were encrypted by the ransomware"
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
	printf(" ");// <----- WITHOUT THIS IS GOING TO CRASH FOR SOME REASON.... :-/
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
		tokenFile = (char *)malloc(sizeof(char )*(strlen(token)+1));
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

		free(tokenFile);
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
/* ================== ASSIGN 5 ================== */

void list_encrypted_files(FILE *log)
{
	char *token;
	char *space = " ";
	char *dot = ".";
	char *tokenFile = NULL;
	char *prevFile = NULL;
	char *tmpToken = NULL;

	int found = 0;
	int MAX = 0xFFF;
	struct entry list_node[MAX];

	char *line=NULL;
	size_t len_line = 0;
	int i=0;

	printf("/* ============ Files encrypted from ransomware ============ */\n");
	while(1)
	{		
		size_t check = getline(&line, &len_line, log);
		if(check==-1)		
			break;

		//User's ID.
		token = strtok(line, space);

		//File's Path/Name.
		token = strtok(NULL, space);
		tokenFile = (char *)malloc(sizeof(char )*(strlen(token)+1));
		tmpToken = (char *)malloc(sizeof(char )*(strlen(token)+1));
		strcpy(tokenFile, token);
		strcpy(tmpToken, token);

		tmpToken = strtok(tmpToken, dot);
		while(1)
		{
			tmpToken = strtok(NULL, dot);
			if(tmpToken == NULL)
				break;

			if(strcmp(tmpToken, "encrypt")==0)
			{
				/* Store Files in Array-Struct so we won't print duplicates */
				if(found == 0)
				{
					printf("%s\n", tokenFile);
					list_node[found].file = (char* )malloc(sizeof(char)*strlen(tokenFile));
					strcpy(list_node[found].file,tokenFile);
					found++;
				}
				else
				{
					bool isExist = false;
					int i=0;
					while(!isExist && i<found)
					{
						if(strcmp(tokenFile, list_node[i].file) == 0)
						{
							isExist = true;
							break;
						}
						i++;
					}

					if(!isExist)
					{
						printf("%s\n", tokenFile);
						list_node[found].file = (char* )malloc(sizeof(char)*strlen(tokenFile));
						strcpy(list_node[found].file,tokenFile);
						found++;
					}
				}
			}

		}

		free(tokenFile);
		free(tmpToken);
	}

	for(int i=0; i<found; i++)
		free(list_node[i].file);
}

bool isLeapYear(int y)
{
    if (y%4 != 0)
        return false;
    else if (y%100 != 0)
        return true;
    else if (y % 400 != 0)
        return false;
    else
        return true;
}

void date_before_20_minutes(char *c_d, char *d, int *m, int *h)
{
	struct tm *ptr;
	time_t rawtime;

	time(&rawtime);
	ptr = gmtime(&rawtime);

	//Current Time.
	int GMT = 2;
	int hour = (ptr->tm_hour+GMT)%24;
	int min = ptr->tm_min;
	int sec = ptr->tm_sec;

	*h=hour;
	*m=min;
    //Current Date.
	int day = ptr->tm_mday;
	int month = ptr->tm_mon + 1;
	int year = (ptr->tm_year) + 1900;

	//Calculate before 20 mins.
    int min_before = min - 20;
    int hour_before = hour;
    int day_before = day;
    int month_before = month;
    int year_before = year;
   	
   	//Hour changes 
    if(min_before < 0)
    {
        min_before = 60 + min_before;
        hour_before--;

        //Day Changes
        if(hour_before < 0)
        {
            hour_before = 23;
            day_before--;
            //Month Changes
            if(day_before < 1)
            {
                month_before--;
                //Year Changes
                if(month_before < 1)
                {
                    month_before = 12;
                    year_before--;
                }

                //Months with 30 or 31 dates.
                if(month_before<=7)
                {
                    if(month_before%2==0)
                        day_before=30;
                    else
                        day_before=31;
                }
                else
                {
                    if(month_before%2==0)
                        day_before=31;
                    else
                        day_before=30;
                }
            }
        }

    }

    //Check if is Leap Year. Only when the previous month is Feb.
    if(month_before == 4 && day_before == 30)
    {
        bool isLeap = isLeapYear(year_before);
        if(isLeap)
            day_before = 29;
        else
            day_before = 28;
    }

    sprintf(c_d, "%d/%d/%d", day, month, year);
    sprintf(d, "%d/%d/%d", day_before, month_before, year_before);


}

void count_recent_files(FILE *log, int X)
{

	/* 
		Just in case if day or month or year 
		are changing before 20 minutes.
	*/

	char date_before20[11];
	char cur_date[11];
	int cur_hour;
	int cur_min;
	date_before_20_minutes(cur_date, date_before20, &cur_min, &cur_hour);
	
	char *token;	
	char *token_time;
	char *token_date;
	int token_hour;
	int token_min;
	int token_access;

	char *space = " ";
	char *colon = ":";

	char *line=NULL;
	size_t len_line = 0;
	int count = 0;

	/*
		 Read Lines from log file until the time and date are
		 equal 20 minutes before the current date and time.
	*/
	while(1)
	{		
		size_t check = getline(&line, &len_line, log);
		if(check==-1)		
			break;

		//User ID.
		token = strtok(line, space);

		//File Name.
		token = strtok(NULL, space);

		//Date.
		token = strtok(NULL, space);
		token_date = (char*)malloc(sizeof(char)*strlen(token));
		strcpy(token_date, token);

		//Time.
		token = strtok(NULL, space);
		token_time = (char*)malloc(sizeof(char)*strlen(token));
		strcpy(token_time, token);

		//Access Type.
		token = strtok(NULL, space);
		token_access = atoi(token);

		//In case the date is changing before 20 minutes.
		if((strcmp(token_date, date_before20) == 0) || (strcmp(token_time, cur_date) == 0))
		{
			/*
				As long as i have found the correct date in log, now my only
				concern is the difference between 2 times 
			*/

			//Hour
			token_hour = atoi(strtok(token_time, colon));
			//Minute
			token_min = atoi(strtok(NULL, colon));
			
			int diff = cur_min - token_min;
			if(diff<0)
			{
				diff = 60 + diff;
				// Before 20 the hour is changed.
				// So, i am adding one to the token_hour value.
				// Then, token_hour must be equal with current hour in order to have 20mins difference.
				// Imagine the case cur_hour = 15:15 and token_hour 13:59. Mins diff = 16 but hour diff = 2.
				// In case 15:15 and token_hour 14:59 mins diff = 16 and hour diff = 1 but total time diff = 16mins.
				token_hour++;
			}

			if(diff<=20 && token_hour == cur_hour)
			{
				if(token_access == 2)
					count++;
				break;
			}
		}
		
	}

	/* Now the rest lines are belong in desire time range. */
	while(1)
	{		
		size_t check = getline(&line, &len_line, log);
		if(check==-1)		
			break;

		//User ID.
		token = strtok(line, space);

		//File Name.
		token = strtok(NULL, space);

		//Date.
		token = strtok(NULL, space);

		//Time.
		token = strtok(NULL, space);

		//Access Type.
		token = strtok(NULL, space);
		token_access = atoi(token);

		if(token_access == 2)
			count++;
	}

	printf("Files create in last 20 minutes: %d\n", count);
	if(count >= X)
		printf("RANSOMWARE ATTACK !!!\n");
	else
		printf("Naaaaaah, just usual. We are safe :).\n");

}


int main(int argc, char *argv[])
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

	while ((ch = getopt(argc, argv, "hi:hv:m:e")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'e':
			list_encrypted_files(log);
			break;
		case 'v':
			count_recent_files(log, atoi(optarg));
			break;
		default:
			usage();
		}

	}

	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
