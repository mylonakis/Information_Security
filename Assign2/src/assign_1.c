#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *, int);
int decrypt(unsigned char *, int, unsigned char *, unsigned char *,  unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);

/* TODO Declare your function and varaibles prototypes here... */
unsigned char* file_to_buffer(FILE* );
void buffer_to_file(char*, unsigned char*);
int cipherlen;


/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* My Variables */
	unsigned char *key;

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;

	/* My Init arguments */
	key = NULL;

	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);

	/* TODO Develop the logic of your tool here... */
	/* TASK A */
	
	key = (unsigned char*) malloc(bit_mode/8);
	keygen(password, key, NULL, bit_mode);

	/* TASK B */
	if(op_mode == 0)
	{
		FILE *in = fopen(input_file, "r");

		unsigned char *plaintext = file_to_buffer(in);
		int plaintext_len = strlen((const char*) plaintext);

		char *ciphertext = (char *) malloc((sizeof(char *) * plaintext_len)/8);

		encrypt(plaintext, plaintext_len, key, NULL, (unsigned char *)ciphertext, bit_mode);

		buffer_to_file(output_file, (unsigned char *) ciphertext);	

		fclose(in);
		free(plaintext);
		free(ciphertext);
	}
	/* TASK C */
	if(op_mode == 1)
	{
		FILE *in = fopen(input_file, "r");
		unsigned char *ciphertext = file_to_buffer(in);

		int ciphertext_len = strlen((const char*)ciphertext);
		unsigned char *plaintext = (unsigned char *)malloc((sizeof(char *) * ciphertext_len)/8);

		decrypt(ciphertext, ciphertext_len, key, NULL, plaintext, bit_mode);

		buffer_to_file(output_file, plaintext);
		fclose(in);
		free(plaintext);
		free(ciphertext);
	}


	/* TASK D */
	if(op_mode == 2)
	{	
		/* DO TASK A FIRST */
		FILE *in = fopen(input_file, "r");
		
		unsigned char *plaintext = NULL;
		size_t buf_len = strlen((char *)file_to_buffer(in));
		plaintext = (unsigned char*)malloc(sizeof(unsigned char *)*buf_len);
		plaintext = file_to_buffer(in);
		

		size_t plaintext_len = strlen((const char*)plaintext);
		char *ciphertext = (char *) malloc(sizeof(char) * plaintext_len);

		encrypt(plaintext, plaintext_len, key, NULL, (unsigned char *)ciphertext, bit_mode);	

		unsigned char *cmac = (unsigned char *)malloc(sizeof(char *) * plaintext_len);

		gen_cmac(plaintext, plaintext_len, key, cmac, bit_mode);

		char *data = (char *)malloc( sizeof(char *) * strlen((char *)cmac) * strlen((char *)ciphertext) );
		strcpy(data, (char *)cmac);
		strcat(data, (char *)ciphertext);

		buffer_to_file(output_file, (unsigned char*) data);

		free(plaintext);
		free(ciphertext);
		free(cmac);
		fclose(in);
	}

	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);

	/* My Clean up */
	free(key);
	

	/* END */
	return 0;
}
/* TODO Develop your functions here... */
unsigned char *file_to_buffer(FILE *fp)
{
	if(fp == NULL)
	{
		printf("Empty File\n Byeeee...\n");
		exit(1);
	}

	/* Get the number of bytes */
	fseek(fp, 0, SEEK_END);
	/* ftell returns the current value of the position indicator */
	long numbytes = ftell(fp);

	/* reset the file position indicator to 
	the beginning of the file */
	fseek(fp, 0, SEEK_SET);	

	/* grab sufficient memory for the 
	buffer to hold the text */
	unsigned char *buffer = (unsigned char*)malloc(sizeof(char)*numbytes);

	if(buffer == NULL)
	{
		perror("Error: Memory Allocation");
		exit(1);
	}

	size_t check = fread(buffer, sizeof(char), numbytes, fp);

	if(!check)
	{
		perror("Error: Reading File");
		exit(1);
	}

	return buffer;
}
void buffer_to_file(char *out, unsigned char *buf)
{
	FILE *fp = fopen(out, "w+b");	
	
	fwrite(buf, 1, strlen((const char *)buf), fp);

	fclose(fp);
}
/*
 * Generates a key using a password
 */
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv, int bit_mode)
{
	int passlen = strlen((const char *)password);
	int keylen = bit_mode/8;

    int check = PKCS5_PBKDF2_HMAC_SHA1((const char *)password, passlen, NULL, 0, 1, keylen, key);
    if(!check)
    	perror("Error: PKCS5_PBKDF2_HMAC_SHA1");	
}


/*
 * Encrypts the data
 */
void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{
	EVP_CIPHER_CTX *cctx;
	const EVP_CIPHER *evpc;
	int len;
	int updateLen = plaintext_len + BLOCK_SIZE - 1;

	cctx = EVP_CIPHER_CTX_new();

	if(bit_mode == 128)
	{
		evpc = EVP_aes_128_ecb();
	}
	else
	{
		evpc = EVP_aes_256_ecb();	
	}
	EVP_EncryptInit_ex(cctx, evpc, NULL, key, NULL);
    
    EVP_CIPHER_CTX_set_padding(cctx, BLOCK_SIZE);

    EVP_EncryptUpdate(cctx, ciphertext, &len, plaintext, updateLen); 	
	
	EVP_EncryptFinal_ex(cctx, (ciphertext + len), &updateLen); 	
    
    // for some reason core dumps, but is working..
    //EVP_CIPHER_CTX_free(cctx);
}


/*
 * Decrypts the data and returns the plaintext size
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	int len;
	EVP_CIPHER_CTX *cctx;
	const EVP_CIPHER *evpc;
	int updateLen = ciphertext_len + BLOCK_SIZE - 1;

	cctx = EVP_CIPHER_CTX_new();

	if(bit_mode == 128)
		evpc = EVP_aes_128_ecb();
	else
		evpc = EVP_aes_256_ecb();

	EVP_DecryptInit_ex(cctx, evpc, NULL, key, NULL);

	EVP_CIPHER_CTX_set_padding(cctx, BLOCK_SIZE);
	
	EVP_DecryptUpdate(cctx, plaintext, &len, ciphertext, updateLen);
	
	EVP_DecryptFinal_ex(cctx, (plaintext + len), &len);
	
	EVP_CIPHER_CTX_free(cctx);

	return 0;
}


/*
 * Generates a CMAC
 */
void gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, unsigned char *cmac, int bit_mode)
{
	CMAC_CTX *cmctx;
	const EVP_CIPHER *evpc;

	cmctx = CMAC_CTX_new();
	if(cmctx == NULL)
		perror("Error:CMAC_CTX_new");

	if(bit_mode == 128)
		evpc = EVP_aes_128_ecb();
	else
		evpc = EVP_aes_256_ecb();

	CMAC_Init(cmctx, key, strlen((char *)key), evpc, NULL);
	
	CMAC_Update(cmctx, data, strlen((char *)data));

	CMAC_Final(cmctx, cmac, &data_len);

	CMAC_CTX_free(cmctx);

}


/*
 * Verifies a CMAC
 */
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 0;

	/* TODO Task E */

	return verify;
}
/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}
