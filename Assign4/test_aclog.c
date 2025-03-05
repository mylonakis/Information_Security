#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>


#define TIMES 100
#define UNTIL_File_x 11

int main() 
{
	int firstTime = 1;
	size_t bytes;
	FILE *file;
	char filenames[12][7] = {"file_0", "file_1", "file_2", "file_3",
							"file_4", "file_5", "file_6", "file_7",
							"file_8", "file_9", "file10", "file11" };
	/* Clear Log File */
	FILE *logfp = fopen("file_logging.log", "w+");
	fclose(logfp);
	
	/* Clean directory's files if they exist.*/
	for(int i=0; i <= UNTIL_File_x; i++)
	{
		if(access(filenames[i], F_OK)!=-1)
		{
			char rm_cmd[15];
			if(i<=9)
				sprintf(rm_cmd,"rm file_%d", i);
			else
				sprintf(rm_cmd,"rm file%d", i);

			system(rm_cmd);
		}			
	}

	 /* Intializes random number generator */
	time_t t; 
	srand( time(&t) ); //Seed for random().	

	/*
		Creating
		Mode w
	*/
	for(int i=0; i <= UNTIL_File_x; i++)
	{		
		file = fopen(filenames[i], "w");
		if(file != NULL)
			fclose(file);
	}

	for(int j=1; j<=TIMES; j++)
	{
		for(int i=0; i <= UNTIL_File_x; i++)
		{	
			file = fopen(filenames[i], "a+");
			if(file != NULL)
			{	
				bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
				fclose(file);
			}
		}
	}	
    return 0;
}
