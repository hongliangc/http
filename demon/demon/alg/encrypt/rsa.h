#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <limits.h>

#define RSA_1_
#ifdef RSA_1_

/**
* Basic limb type. Note that some calculations rely on unsigned overflow wrap-around of this type.
* As a result, only unsigned types should be used here, and the RADIX, HALFRADIX above should be
* changed as necessary. Unsigned integer should probably be the most efficient word type, and this
* is used by GMP for example.
*/
typedef unsigned int word;

/* Accuracy with which we test for prime numbers using Solovay-Strassen algorithm.
* 20 Tests should be sufficient for most largish primes */
#define ACCURACY 20

#define FACTOR_DIGITS 100
#define EXPONENT_MAX RAND_MAX
#define BUF_SIZE 1024

/* Initial capacity for a bignum structure. They will flexibly expand but this
* should be reasonably high to avoid frequent early reallocs */
#define BIGNUM_CAPACITY 20

/* Radix and halfradix. These should be changed if the limb/word type changes */
#define RADIX 4294967296UL
#define HALFRADIX 2147483648UL

#define MAX(a,b) ((a) > (b) ? (a) : (b))

#define BLOCK_SIZE_  82
#define BLOCK_LENGTH  21
#define BLOCK_LENGTH_BYTES (int)(BLOCK_LENGTH * sizeof(int) / sizeof(char))

/**
* Structure for representing multiple precision integers. This is a base "word" LSB
* representation. In this case the base, word, is 2^32. Length is the number of words
* in the current representation. Length should not allow for trailing zeros (Things like
* 000124). The capacity is the number of words allocated for the limb data.
*/
typedef struct _bignum {
	int length;
	int capacity;
	word* data;
} bignum;

// ============================================================================
// code wrote myself
int decodeString(char* src, int src_len, char** des, int *des_len, bignum* exp, bignum* mod);
int encodeString(char* src, int src_len, char** des, int *des_len, bignum* exp, bignum* mod);
char* decodeStringChar(char* src, int src_len, char* exp_, int exp_len, char* mod_, int mod_len);
char* encodeStringChar(int *dest_len, char* src, int src_len, char* exp_, int exp_len, char* mod_, int mod_len);
char* encodeBytes(char* src, int len, int bytes, bignum* exp, bignum* mod);
char* decodeBytes(char* src, int len, int bytes, bignum* exp, bignum* mod);
char* encodeBytesChar(char* src, int len, int bytes, char* buf, char* exp_, int exp_len, char* mod_, int mod_len);
char* decodeBytesChar(char* src, int len, int bytes, char* buf, char* exp_, int exp_len, char* mod_, int mod_len);
void gen_rsa_key(bignum** pub_exp, bignum** pub_mod, bignum** priv_exp, bignum** priv_mod, int* bytes);
int get_encode_info(int len, int bytes, int* pck_num);
int get_decode_info(int len, int bytes, int* pck_num);
bignum *encodeMessage(int len, int bytes, char *message, bignum *exponent, bignum *modulus);
char *decodeMessage(int len, int bytes, bignum *cryptogram, bignum *exponent, bignum *modulus);
char itoc(char i);

int GetBlockSize(bignum* mod);
// ============================================================================

void str_inverse(char* str);
bignum* bignum_init();
void bignum_deinit(bignum* b);
int bignum_iszero(bignum* b);
int bignum_isnonzero(bignum* b);
void bignum_copy(bignum* source, bignum* dest);
int bignum_fromstring(bignum* b, char* string, int len);
int bignum_fromhexstring(bignum* b, char* string, int len);
void bignum_fromint(bignum* b, unsigned int num);
void bignum_print(bignum* b);
char* bignum_tostring(bignum* b, int *pLen);
int bignum_equal(bignum* b1, bignum* b2);
int bignum_greater(bignum* b1, bignum* b2);
int bignum_less(bignum* b1, bignum* b2);
int bignum_geq(bignum* b1, bignum* b2);
int bignum_leq(bignum* b1, bignum* b2);
void bignum_iadd(bignum* source, bignum* add);
void bignum_add(bignum* result, bignum* b1, bignum* b2);
void bignum_isubtract(bignum* source, bignum* add);
void bignum_subtract(bignum* result, bignum* b1, bignum* b2);
void bignum_imultiply(bignum* source, bignum* add);
void bignum_multiply(bignum* result, bignum* b1, bignum* b2);
void bignum_idivide(bignum* source, bignum* div);
void bignum_idivider(bignum* source, bignum* div, bignum* remainder);
void bignum_remainder(bignum* source, bignum *div, bignum* remainder);
void bignum_imodulate(bignum* source, bignum* modulus);
void bignum_divide(bignum* quotient, bignum* remainder, bignum* b1, bignum* b2);
void bignum_modpow(bignum* base, bignum* exponent, bignum* modulus, bignum* result);
void bignum_gcd(bignum* b1, bignum* b2, bignum* result);
void bignum_inverse(bignum* a, bignum* m, bignum* result);
int bignum_jacobi(bignum* ac, bignum* nc);
int solovayPrime(int a, bignum* n);
int probablePrime(bignum* n, int k);
void randPrime(int numDigits, bignum* result);
void randExponent(bignum* phi, int n, bignum* result);
int readFile(FILE* fd, char** buffer, int bytes);
void encode(bignum* m, bignum* e, bignum* n, bignum* result);
void decode(bignum* c, bignum* d, bignum* n, bignum* result);


#elif defined(RAS2)

bool addbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n);
bool subbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n);
bool modbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n);
bool modnum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n);
bool modmult1024(uint64_t res[], uint64_t op1[], uint64_t op2[], uint64_t mod[]);
int rsa1024(uint64_t res[], uint64_t data[], uint64_t expo[], uint64_t key[]);
bool multbignum(uint64_t res[], uint64_t op1[], uint32_t op2, uint32_t n);
uint32_t bit_length(uint64_t op[], uint32_t n);
int32_t compare(uint64_t op1[], uint64_t op2[], uint32_t n);
bool slnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n);//shift left by n
bool srnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n);

int test_rsa(void)
#else

typedef int64_t integer;
/* B is the base of the bignum system, it has to be an exponention of 2 */
#define B 16
#define E 4      // B = 2^E, E = 1, 2, ..., 31
#define MASK 0xf


// This is the security parameter t in fermats test
#define TEST_CNT 10


/*
* This structure is used to store a bignum.
* sign: If sign of a number is -ve then this sign is stored as -1 and if
* 		 bignum is +ve then the sign is stored as +1
* size: If is the size of the array tab
* tab : This array is used to store the bignum
* */

typedef struct {
	int sign;
	int size;
	integer *tab;
} bignum;


bignum str2bignum(char * str);
bignum add(bignum a, bignum b);
bignum sub(bignum a, bignum b);
bignum mult(bignum a, bignum b);
bignum reminder(bignum a, bignum n);
bignum addmod(bignum a, bignum b, bignum n);
bignum multmod(bignum a, bignum b, bignum n);
bignum expmod(bignum a, bignum b, bignum n);
int fermat(bignum a, int t);
bignum genrandom(int len);
bignum genrandomprime(int len);


// other utility functions

int length(bignum a);
bignum digit2bignum(int d);
void printbignum(bignum a);
int iszero(bignum a);
int isone(bignum a);
int isnormalized(bignum a);
int compare(bignum a, bignum b);
void copy(bignum *dest, bignum src);
bignum leftshift(bignum a, int k);
bignum rightshift(bignum a, int k);
bignum inverse(bignum a, bignum n);
bignum gcd(bignum a, bignum b);
bignum divi(bignum a, bignum n);
bignum * normalized_divi(bignum a, bignum b);


// Test methods
void testStr2bignum();
void testAddition();
void testSubtraction();
void testMultiplication();
void testRemainder();
void testAdditionModulus();
void testMultiplicationModulus();
void testExponentialModulus();
void testFermat();
void testGenerateRandom();
void testGenerateRandomPrime();

void keygen(bignum * n, bignum * e, bignum * d, int length);
bignum RSAencrypt(bignum m, bignum e, bignum n);
bignum RSAdecrypt(bignum c, bignum d, bignum n);
void testRSA(int length);

#endif