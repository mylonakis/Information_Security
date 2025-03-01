#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include "simple_crypto.h"


int main()
{	
	otp_numb = NULL;
	caesar_numb = NULL;
	vig_numb = NULL;
	vig_key = NULL;
	/* ================================== ONE TIME PAD ====================================== */
	otp_numb = (unsigned char*)(malloc(sizeof(char)*1000));	

	printf("[OTP] input: ");
	scanf(" %s", otp_numb);
	
	skipChars_otp_cae(otp_numb);
	
	otp_keys = (unsigned char*)(malloc(sizeof(unsigned char)*inputLenght));	
	otpPrintableNumber = (unsigned char*)(malloc(sizeof(unsigned char)*inputLenght));

	otp_urandom();

	one_time_pad_en();	
	printf("[OTP] encrypted: ");
	print_proccessed_number(otpPrintableNumber);

	one_time_pad_de();	
	printf("[OTP] decrypted: ");
	print_proccessed_number(otp_numb);


	free(otp_numb);
	free(otpPrintableNumber);
	free(otp_keys);

	/* ================================== CAESARS ====================================== */

	caesar_numb = (unsigned char*)(malloc(sizeof(char)*1000));
	
	initArray();
	
	printf("[Caesars] input: ");
	scanf(" %s", caesar_numb);
	skipChars_otp_cae(caesar_numb);

	printf("[Caesars] key: ");
	scanf(" %d", &caesar_key);
	
	caesar_en();
	printf("[Caesars] encrypted: ");
	print_proccessed_number(caesar_numb);

	caesar_de();
	printf("[Caesars] decrypted: ");
	print_proccessed_number(caesar_numb);

	free(caesar_numb);

	/* ================================== VIGENERE ====================================== */

	vig_numb = (unsigned char*)(malloc(sizeof(char)*1000));
	vig_key = (unsigned char*)(malloc(sizeof(char)*1000));
	initTabulaRecta();

	printf("[Vigenere] input: ");
	scanf(" %s", vig_numb);
	skipChars_veg(vig_numb, 0);

	printf("[Vigenere] key: ");
	scanf(" %s", vig_key);
	skipChars_veg(vig_key, 1);

	vig_en();
	printf("[Vigenere] encrypted: ");
	print_proccessed_number(vig_numb);

	vig_de();
	printf("[Vigenere] decrypted: ");
	print_proccessed_number(vig_numb);

	free(vig_numb);
	free(vig_key);

	return 0;
	

}