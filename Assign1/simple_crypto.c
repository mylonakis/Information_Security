#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include "simple_crypto.h"

void print_proccessed_number(char* num)
{
	
	for(int i=0; i<inputLenght; i++)
		printf("%c", (unsigned char)(*(num+i)));

	printf("\n");

}

/* ================================== ONE TIME PAD ====================================== */
void skipChars_otp_cae(char *in)
{

	unsigned char *tempPlainText = (unsigned char *)(malloc(sizeof(unsigned char*)*strlen(in)));

	int i = 0;
	int j = 0;
	while(*(in + i) != '\0')
	{
		if(isalnum(*(in + i)))
		{
			*(tempPlainText + j) = *(in + i);
			j++;
		}

		i++;
	}

	*(tempPlainText + j) = '\0';
	inputLenght = strlen(tempPlainText);

	if(otp_numb != NULL)
		strcpy(otp_numb, tempPlainText);

	if(caesar_numb != NULL)
		strcpy(caesar_numb, tempPlainText);

	free(tempPlainText);
}

void otp_urandom()
{
	unsigned char* buf = (unsigned char*)(malloc(sizeof(unsigned char)));

	FILE* fp = fopen("/dev/urandom", "r");

	int loops = 0;
	long int seek = 0;
	fseek(fp, 0, SEEK_SET);
	
	while(loops < inputLenght)
	{
		fgets(buf, 2, fp);
		
		
		if( isalnum(*buf))
		{
			*(otp_keys+loops) = (unsigned char)(*buf);
			loops++;
		}

		seek++;
		fseek(fp, seek, SEEK_CUR);

	}
	free(buf);
	fclose(fp);

}

void one_time_pad_en()
{

	uint modFromCeil;
	
	for(int i=0; i<inputLenght; i++)
	{
		*(otp_numb+i) = (unsigned char)(*(otp_numb+i) ^ *(otp_keys+i));		
		*(otpPrintableNumber+i) = (unsigned char)(*(otp_numb+i) + *(otp_keys+i));
		
		if((unsigned char)(*(otpPrintableNumber+i)) > CEIL)
		{
			modFromCeil = ((uint)(*(otp_keys+i)) % CEIL);
			
			while((modFromCeil + FLOOR) > CEIL)			
				modFromCeil = (modFromCeil + FLOOR) % CEIL;			

			*(otpPrintableNumber+i) = (unsigned char)(modFromCeil + FLOOR);
		}
	}

}

void one_time_pad_de()
{

	uint modFromCeil;
	
	for(int i=0; i<inputLenght; i++)
	{
		*(otp_numb+i) = (unsigned char)(*(otp_numb+i) ^ *(otp_keys+i));
	}
}

/* ================================== CAESARS ====================================== */

void initArray()
{	
	char data = '0';
	
	for(int i=0; i<ARRAY_SIZE; i++)
	{
		if(data == 58)
			data = 'A';
		
		if(data == 91)
			data = 'a';

		alphaNum[i] = data;
		data++;
	}		

}

void  locatel(int p)
{
	letterPos = 0;
	while(alphaNum[letterPos] != *(caesar_numb+p) && letterPos < ARRAY_SIZE)
		letterPos++;
}

void caesar_en()
{
	int i=0;
	int pos = 0;
	locatel(i);
	while( i<inputLenght )
	{
		if(letterPos + (caesar_key) >= ARRAY_SIZE )
			pos = caesar_key - (ARRAY_SIZE - letterPos);
		else if (letterPos+caesar_key < 0)
			pos = (ARRAY_SIZE + letterPos) - caesar_key;
		else
			pos = letterPos+caesar_key;

		*(caesar_numb+i) = alphaNum[pos];
		i++;
		pos++;
		locatel(i);
	}
}

void caesar_de()
{
	int i=0;
	int pos = 0;
	locatel(i);
	while( i<inputLenght )
	{
		if(letterPos-caesar_key < 0 )
			pos = (ARRAY_SIZE + letterPos) - caesar_key;
		else if (letterPos-caesar_key >= ARRAY_SIZE)
			pos = caesar_key - (ARRAY_SIZE - letterPos);
		else
			pos = letterPos-caesar_key;

		*(caesar_numb+i) = alphaNum[pos];
		i++;
		pos++;
		locatel(i);
	}
}

/* ================================== VIGENERE ====================================== */
void skipChars_veg(char *in, int _case_)
{

	unsigned char *tempPlainText = (unsigned char *)(malloc(sizeof(unsigned char*)*strlen(in)));

	int i = 0;
	int j = 0;
	while(*(in + i) != '\0')
	{
		if(isalnum(*(in + i)) && !isdigit(*(in + i)) && isupper(*(in + i)))
		{
			*(tempPlainText + j) = *(in + i);
			j++;
		}

		i++;
	}

	*(tempPlainText + j) = '\0';


	if(_case_ == 0)
	{
		strcpy(vig_numb, tempPlainText);
		inputLenght = strlen(vig_numb);
	}
	else
	{
		strcpy(vig_key, tempPlainText);
		vig_key_len = strlen(vig_key);
	}

	free(tempPlainText);
}

void initTabulaRecta()
{
	char data = 'A';
	int i = 0;
	int j = 0;
	int index = 0;
	
	int symmetricLoops = ROWS-1;
	int index2 = 0;
	int y = 1;
	while(data <= 90 && index < ROWS)
	{
		while(i>=0 && j<=index)
		{
			TabRec[i][j] = data;
			i--;
			j++;
		}

		while(index2 < symmetricLoops)
		{
			TabRec[(ROWS-1)-index2][y + index2] = data;
			index2++;
		}

		y++;
		index2 = 0;
		symmetricLoops--;
		index++;
		data++;
		j=0;
		i=index;
	}
}

void findIndicators_en(int l, int k)
{
	rowIndicator = 0;
	colIndicator = 0;

	while(TabRec[0][colIndicator] != *(vig_numb + l))
		colIndicator++;

	while(TabRec[rowIndicator][0] != *(vig_key + k))
		rowIndicator++;
}

void vig_en()
{
	int i=0;
	int k=0;
	while(i<inputLenght)
	{
		findIndicators_en(i, k);
		*(vig_numb+i) = TabRec[rowIndicator][colIndicator];

		if(*(vig_key + (k+1)) == '\0')
			k=0;
		else
			k++;
		i++;

	}
}

void vig_de()
{
	int i=0;
	int k=0;
	while(i<inputLenght)
	{
		findIndicators_de(i, k);
		*(vig_numb+i) = TabRec[0][colIndicator];

		if(*(vig_key + (k+1)) == '\0')
			k=0;
		else
			k++;
		i++;

	}
}

void findIndicators_de(int l, int k)
{
	rowIndicator = 0;
	colIndicator = 0;

	while(TabRec[rowIndicator][0] != *(vig_key + k))
		rowIndicator++;

	while(TabRec[rowIndicator][colIndicator] != *(vig_numb + l))
		colIndicator++;
}