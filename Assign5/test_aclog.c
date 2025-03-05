#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <dirent.h>
#include <errno.h>

#define UNTIL_File_x 200

int main(int argc, char *argv[])
{
	int MAX = 0xFFF;

	// For ransomware to create big volume of file.
	if(argc > 1)
	{
		int x = atoi(argv[1]);
		for(int i=0; i<x; i++)
		{
			char buf[MAX];
			char file[MAX];

			sprintf(file, "files/file_%d.txt", i);
			sprintf(buf,  "dummy %d", i);
			FILE *fp = fopen(file, "w+");
			if(file != NULL)
			{
				fwrite(buf, strlen(buf), 1, fp);
				fclose(fp);
			}

		}

		return 0;
	}

	char buf[MAX];
	int firstTime = 1;
	size_t bytes;
	FILE *file;
	char all_files[UNTIL_File_x+1][MAX];

	/* Clear Log File */
	FILE *logfp = fopen("file_logging.log", "w+");
	fclose(logfp);

	/* Get Current Directory. */
	char pwd[MAX];
	getcwd(pwd, sizeof(pwd));

	/*	Create Directory for User's Files.
		Also in this directory i ll test my ransomware.	*/	
	char userDir[MAX];
	char toDelete[MAX];
	sprintf(userDir,"%s/files", pwd);

	/* Check If User's directory already exists */
	DIR* dir = opendir(userDir);
	/* Directory exists. Delete its files.*/
	if (dir)
	{
		sprintf(toDelete, "exec rm -r %s/*", userDir);
		system(toDelete);
	    closedir(dir);
	}
    /* Directory does not exist. Create it.*/
	else if (ENOENT == errno)
		mkdir(userDir, 0777);

	/* Clean directory's files if atleast one exists.*/
	for(int i=0; i <= UNTIL_File_x; i++)
	{
		char user_file[MAX];
		sprintf(user_file, "%s/file_%d.txt", userDir, i);
		strcpy(all_files[i],user_file);	

		file = fopen(all_files[i], "w+");
		if(file != NULL)
		{
			char toWrite[MAX];
			sprintf(toWrite, "Info %d\n", i);
			fwrite(toWrite, strlen(toWrite), 1, file);
			fclose(file);
		}
	}

    return 0;
}
