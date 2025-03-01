int inputLenght;
void print_proccessed_number(char* alnum);

/* ================================== ONE TIME PAD ====================================== */
#define FLOOR 33
#define CEIL 126
#define RANGE 93

unsigned char* otp_keys;
char *otp_numb;
char *otpPrintableNumber;

void skipChars_otp_cae(char *in);
void otp_urandom();
void one_time_pad_en();
void one_time_pad_de();


/* ================================== CAESARS ====================================== */
#define ARRAY_SIZE 62
char alphaNum[ARRAY_SIZE];

void initArray();

char *caesar_numb;
int caesar_key;
int letterPos;

void locateLetter(int p);
void caesar_en();
void caesar_de();

/* ================================== VIGENERE ====================================== */
#define COLUMNS 26
#define ROWS 26
char TabRec[ROWS][COLUMNS];

char *vig_numb;
char *vig_key;
int vig_key_len;
int rowIndicator;
int colIndicator;

void initTabulaRecta();
void skipChars_veg(char *in, int _case_);
void vig_en();
void vig_de();
void findIndicators_en(int l, int k);
void findIndicators_de(int l, int k);