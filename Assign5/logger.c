#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <dirent.h>
#include <libgen.h>
#include <errno.h>

char *file_to_buffer(FILE *fp, long *file_size)
{
	long curr_pos = ftell(fp);
	//Seek on the end of file
	fseek(fp, 0, SEEK_END);
	//Count bytes in order to allocate memory correctly.
	long numbytes = ftell(fp);
	//Seek back to start of file.
	fseek(fp, 0, SEEK_SET);
	//Allocate appropriate size fro buffer.
	char *buffer = ( char*)malloc(sizeof(char)*numbytes);
	//Read to buffer.
	fread(buffer, sizeof(char), numbytes, fp);
	//Update buffer's size by reference.
	*file_size = numbytes;

	fseek(fp, curr_pos, SEEK_SET);
	return buffer;
}

int check_privileges(const char * path, uid_t uid)
{
	char *token;
	char *delim = " ";	

	//int MAX = 0xFFF;
	char **filesOwn = (char **)malloc(sizeof(char));
	//char *filesOwn[MAX];
	int owns = 0;
	
	int tokenID, tokenAccess;
	char *tokenFile;

	FILE *log_fp = fopen("file_logging.log", "r");
	char *line=NULL;
	size_t len_line = 0;
	
	/* Find files user owns */
	while(1)
	{	
		size_t check = getline(&line, &len_line, log_fp);
		if(check==-1)		
			break;

		//User's ID.
		token = strtok(line, delim);
		tokenID = atoi(token);

		//File's Path/Name.
		tokenFile = strtok(NULL, delim);
	
		//Log in Date.
		token = strtok(NULL, delim);

		//Log in Time.
		token = strtok(NULL, delim);

		//Access Type.
		token = strtok(NULL, delim);
		tokenAccess = atoi(token);

		if((tokenAccess == 0 && tokenID == uid))
		{
			owns++;
			filesOwn = (char **)realloc(filesOwn, sizeof(char *)*owns);		
			filesOwn[owns-1] = (char *)malloc(sizeof(char)*(strlen(tokenFile)+1));		
			strcpy(filesOwn[owns-1], tokenFile);
		}
	}

	fclose(log_fp);
	int flag = 1;
	/* Deny if owns nothing */
	if(owns == 0)
		return flag;
	/*
		Check if the file this user trying to
		access have privileges to do so.
	*/

	for(int i=(owns-1); i>=0; i--)
	{
		if(strcmp(path, filesOwn[i]) == 0)
		  flag = 0;

		free(filesOwn[i]);
	}

    free(filesOwn);
	return flag;
}

/*
	Prints the log events in file file_logging.log.
	Seperates each information by a single space.
	Prints Infos with the exact order as the steps
	in anouncement are represented.
*/

void log_event(FILE *file, const char *path, uid_t uid, int accessType, int isAction)
{	

	FILE *logfp = fopen("file_logging.log", "a+");

	//1. UID.
	fprintf(logfp, "%d ", uid);

	//2. File name.
	fprintf(logfp, "%s ", path);

	//3. Date.
	struct tm *ptr;
	time_t rawtime;

	time(&rawtime);
	ptr = gmtime(&rawtime);

	int day = ptr->tm_mday;
	int month = ptr->tm_mon + 1;
	int year = (ptr->tm_year) + 1900;

	fprintf(logfp, "%d/%d/%d ", day, month, year);
	
	//4. Timestamp.
	int GMT = 2;
	int hour = (ptr->tm_hour+GMT)%24;
	int mins = ptr->tm_min;
	int secs = ptr->tm_sec;

	fprintf(logfp, "%2d:%02d:%02d ", hour, mins, secs);

	//5. Access Type as argument.    
	fprintf(logfp, "%d ", accessType);

	//6. Is-a​ction-denied.
	fprintf(logfp, "%d ", isAction);

	//​7. File fingerprint​. *md = NULL => the digest is placed in a static array.
	long file_size = 0;
	char *file_content;
	unsigned char *md5;

	file_content = file_to_buffer(file, &file_size);

	md5 = (unsigned char *) malloc(MD5_DIGEST_LENGTH);
	MD5((unsigned char *) file_content, file_size, md5);
	
	/* Write md5's hex values in file */
	for(int i=0; i < MD5_DIGEST_LENGTH; i++)
		fprintf(logfp, "%02x", md5[i]);
	
	fprintf(logfp, "\n");

	free(file_content);
	free(md5);
	fclose(logfp);
}

FILE *fopen(const char *path, const char *mode) 
{	
	/*
		Check if input file is our log file.
		Return file pointer immediately.
		In this case our fopen() works 
		like C's fopen().
	*/

    if(strcmp(path, "file_logging.log") == 0)
	{
		FILE *original_fopen_ret;
		FILE *(*original_fopen)(const char*, const char*);

		original_fopen = dlsym(RTLD_NEXT, "fopen");
		original_fopen_ret = (*original_fopen)(path, mode);
		return original_fopen_ret;
	}
	//Need to do this first in order to check the existance of file correctly.	
	int accessType = 0;
	if(access(path, F_OK)!=-1)
		accessType = 1;
	//else if((strcmp(mode, "r") == 0) || (strcmp(mode, "r+") == 0) )			
		//return NULL;	

	/* Reading and understading about Complicated declarations in C the below command means.
	   The variable original_fopen is a pointer to a function. 
	   This function has as arguments 2 variables with data
	   type const char* and returns a file pointer FILE *.
	*/

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	//Simulate a user.
	//uid_t r_uid = (rand()%(1004 - 1000 + 1) + 1000); //Derive user's id.
	uid_t uid = getuid();

	/* Check Privileges */
	int denied = 0;
	if(access(path, X_OK)== errno)
	{
		denied = 1;
		log_event(original_fopen_ret, path, uid, accessType, denied);
		return original_fopen_ret;
	}
	
	log_event(original_fopen_ret, path, uid, accessType, denied);

	return original_fopen_ret;
}

FILE *fopen64(const char *path, const char *mode)
{
	FILE *fp = fopen(path, mode);
	return fp;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	/*
		At first, by using file pointer
		lets get file's name/path
	*/
	int MAX = 0xFFF;
	char link[MAX];
	char path[MAX];	

	/*
		Find by using File Pointer the file's
		full directory path
	*/
	int fno = fileno(stream);
	sprintf(link, "/proc/self/fd/%d", fno);
    
    ssize_t l = readlink(link, path, MAX);
    if (l < 0)
    {
        printf("failed to readlink\n");
        exit(1);
    }
	
    path[l] = '\0';
    
	//Simulate a user.
	//uid_t r_uid = (rand()%(1004 - 1000 + 1) + 1000); //Derive user's id.
	uid_t uid = getuid();

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");

	int denied = 0;
	if(access(path, X_OK) == errno)
	{
		denied = 1;
		log_event(stream, path, uid, 2, denied);
		return 0;
	}

	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	log_event(stream, path, uid, 2, denied);

	return original_fwrite_ret;
}
