#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <stdbool.h>
#include "rsa.h"
#include "utils.h"

/* ====================================== TASK A ====================================== */

/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */

void rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;	

	// 1. Sieve Of Eratosthenes.	
	size_t *pool_primes = NULL;
	int s = 1000;
	int *primes_size = &s;

	pool_primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, primes_size);
	if(&pool_primes == 0)
		printf("Error: Primes Size is Empty\n");

	// 2. Pick p and q.
	int num1,num2;

	srand(time(0));	
	do{
		num1 = rand()%((*primes_size) + 1);
		num2 = rand()%((*primes_size) + 1);		
	}while(num1==num2);

	p = pool_primes[num1];
	q = pool_primes[num2];

	// 3. Compute n
	n = p*q;

	// 4. Euler's totient.
	fi_n = (p-1)*(q-1);

	// 5. Choose prime e.
	e = choose_e(fi_n);

	// 6. Modular inverse.
	d = mod_inverse(e, fi_n);
	// Of course the way we are generating e and fi_n is guarantee that mod_inverse will exist.
	// But i would like to make a check :).
	if(d == 0)
	{
		printf("Ops. Modular inverse do not exists.\n");
		exit(1);
	}

	// 7. Public Key
	FILE* fp = fopen("public.key", "w");
	fwrite(&n, sizeof(size_t), 1, fp);
	fwrite(&d, sizeof(size_t), 1, fp);

	// 8. Private Key
	fp = fopen("private.key", "w");
	fwrite(&n, sizeof(size_t), 1, fp);
	fwrite(&e, sizeof(size_t), 1, fp);

	fclose(fp);
	free(pool_primes);
}

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */

size_t *sieve_of_eratosthenes(int limit, int *primes_sz)
{
	size_t *primes = NULL;	
	bool A[*primes_sz];

	if(primes_sz == 0)
		return 0;	
	//Set all numbers true. All are primes.
	memset(A, true, sizeof(A));
	//False.O and 1 aren't primes.
	A[0] = false;
	A[1] = false;

	for(int x=2; x*x<(*primes_sz); x++)
	{
		if(A[x] == true)
		{
			for(int j=x*x; j<(*primes_sz); j=j+x)		
				A[j] = false;			
		}		
	}

	primes = (size_t *) malloc(sizeof(size_t)*RSA_SIEVE_LIMIT);
	
	int i = 0;
	for(int x=2; x<limit; x++)
	{
		if(A[x] == true)
		{
			*(primes+i) = x;
			i++;
		}
	}

	*primes_sz = i;

	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */

size_t gcd(size_t a, size_t b)
{
	/*
		Euclidean algorithm.
		We honor Grecians :)
	*/
	if(a==0)
		return b;

	while(b!=0)
	{
		if(a>b)
			a = a-b;
		else
			b = b-a;
	}

	return a;
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t choose_e(size_t fi_n)
{
	size_t e = 2;

	while(e < fi_n)
	{	
		e++;
		if(isprime(e) &&((e % fi_n) != 0) && (gcd(e,fi_n) == 1))
			break;
		
	}

	return e;
}

bool isprime(size_t e)
{
	if(e <= 1)
		return false;

	if(e % 2 == 0 && e > 2)
		return false;

	for(int i=3; i < e; i++)
	{
		if(e % i == 0)
			return false;
	}

	return true;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */

size_t mod_inverse(size_t a, size_t b)
{

	a = a % b;
	for(int i=1; i<b; i++)
	{
		if( (a*i)%b == 1)
			return i;
	}

	return 0;
}

/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */

void rsa_encrypt(char *input_file, char *output_file, char *key_file)
{
	size_t n;
	size_t ed;

	getKey(key_file, &n, &ed);

	FILE* in = fopen(input_file, "r");	

	char *plaintext = file_to_buffer(in);

	FILE* out = fopen(output_file, "wa");	

	int i = 0;
	size_t c_m;

	while(*(plaintext+i) != '\0')
	{
		c_m = power_mod_n((size_t)plaintext[i], ed, n);
		fwrite(&c_m, sizeof(size_t), 1, out);
		i++;
	}

	fclose(in);
	fclose(out);
	free(plaintext);
}

/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */

void rsa_decrypt(char *input_file, char *output_file, char *key_file)
{
	size_t n;
	size_t ed;

	getKey(key_file, &n, &ed);
	
	size_t *ciphertext;
	// Copy Ciphertext to buffer
	FILE *in = fopen(input_file, "r");
	/* Get the number of bytes */
	fseek(in, 0, SEEK_END);
	/* ftell returns the current value of the position indicator */
	long numbytes = ftell(in);
	/* reset the file position indicator to 
	the beginning of the file */
	fseek(in, 0, SEEK_SET);	
	ciphertext = (size_t *) malloc(sizeof(size_t)*numbytes);
	
	int cipher_sz = (int)(numbytes/8);
	
	size_t check = fread(ciphertext, sizeof(size_t), numbytes, in);
	if(!check)
	{
		perror("Error: Reading File");
		exit(1);
	}
	fclose(in);

    char *de_plain = (char *) malloc((sizeof(char))*(cipher_sz));
    FILE* out = fopen(output_file, "w");
	char d_m;
	for(int i=0; i<cipher_sz; i++)
	{
		d_m = (char) power_mod_n(ciphertext[i], ed, n);
		fprintf(out, "%c", d_m);
	}

	fclose(out);
	free(ciphertext);
}
/*
void getCipher(char *input_file, size_t *cipher,  int *cipher_sz)
{
	size_t *buf = (size_t *) malloc(sizeof(size_t));
	
	FILE *in = fopen(input_file, "r");

	int i=0;
	while(1)
	{	
		fread(buf, sizeof(size_t), 1, in);
		if(feof(in))
			break;		

		cipher[i] = buf[0];		
		i++;
	}
	
	*cipher_sz = i;
	fclose(in);
}*/

void getKey(char *key_file, size_t *n, size_t *ed)
{
	FILE *k = fopen(key_file, "r");
	
	size_t *buf = (size_t *)malloc(sizeof(size_t)*2);
	fread(buf, sizeof(size_t), 2, k);

	*n = buf[0];
	*ed = buf[1];

	free(buf);
	fclose(k);	
}

char *file_to_buffer(FILE *fp)
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
	char *buffer = (char*)malloc(sizeof(char)*numbytes);

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

size_t power_mod_n(size_t x, size_t y, size_t n)
{ 
	// Initialize result.
    int result = 1;  
    // Update x if it is more than or equal to n.
    x = x%n; 
  	
  	// In case x is divisible by n. 
    if (x==0) 
    	return 0;
  
    while (y>0) 
    { 
        // If y is odd, multiply x with result.
        if (y%2 == 1) 
            result = (result*x)%n; 
  
        // y must be even now. y = y/2.
        y /= 2; 
        x = (x*x)%n;   
    }

    return result; 
}
