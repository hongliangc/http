
#include "rsa.h"

#ifdef RSA_1_

/**
* Save some frequently used bigintegers (0 - 10) so they do not need to be repeatedly
* created. Used as, NUMS[5] = bignum("5"), etc..
*/
word DATA0[1] = { 0 }; word DATA1[1] = { 1 }; word DATA2[1] = { 2 };
word DATA3[1] = { 3 }; word DATA4[1] = { 4 }; word DATA5[1] = { 5 };
word DATA6[1] = { 6 }; word DATA7[1] = { 7 }; word DATA8[1] = { 8 };
word DATA9[1] = { 9 }; word DATA10[1] = { 10 };


word DATA11[1] = { 11 }; word DATA12[1] = { 12 }; word DATA13[1] = { 13 };
word DATA14[1] = { 14 }; word DATA15[1] = { 15 };; word DATA16[1] = { 16 };


bignum NUMS[17] = { { 1, 1, DATA0 },{ 1, 1, DATA1 },{ 1, 1, DATA2 },
{ 1, 1, DATA3 },{ 1, 1, DATA4 },{ 1, 1, DATA5 },
{ 1, 1, DATA6 },{ 1, 1, DATA7 },{ 1, 1, DATA8 },
{ 1, 1, DATA9 },{ 1, 1, DATA10 },
{ 1, 1, DATA11 },{ 1, 1, DATA12 },{ 1, 1, DATA13 },{ 1, 1, DATA14 },
{ 1, 1, DATA15 },{ 1, 1, DATA16 } };



// ============================================================================
// code wrote myself

/**
* Encode the message of given length, using the public key (exponent, modulus)
* The resulting array will be of size len/bytes, each index being the encryption
* of "bytes" consecutive characters, given by m = (m1 + m2*128 + m3*128^2 + ..),
* encoded = m^exponent mod modulus
*/
bignum *encodeMessage(int len, int bytes, char *message, bignum *exponent, bignum *modulus) {
	/* Calloc works here because capacity = 0 forces a realloc by callees but we should really
	* bignum_init() all of these */
	int i, j;
	unsigned char* data = (unsigned char*)message;
	bignum *encoded = calloc(len / bytes, sizeof(bignum));
	bignum *num256 = bignum_init(), *num256pow = bignum_init();
	bignum *x = bignum_init(), *current = bignum_init();
	bignum_fromint(num256, 256);
	bignum_fromint(num256pow, 1);
	for (i = 0; i < len; i += bytes) {
		bignum_fromint(x, 0);
		bignum_fromint(num256pow, 1);
		/* Compute buffer[0] + buffer[1]*128 + buffer[2]*128^2 etc (base 128 representation for characters->int encoding)*/
		for (j = 0; j < bytes; j++) {
			bignum_fromint(current, data[i + j]);
			bignum_imultiply(current, num256pow);
			bignum_iadd(x, current); /*x += buffer[i + j] * (1 << (7 * j)) */
			bignum_imultiply(num256pow, num256);
		}
		// printf("==================== ENCODED NOT ENCRYPTED ===================\n");
		// int k;
		// for (k = 0; k < x[0].length; ++k) {
		// 	printf("%u\n", x[0].data[k]);
		// }

		encode(x, exponent, modulus, &encoded[i / bytes]);
	}
	return encoded;
}

int encodeString(char* src, int src_len, char** des, int *des_len, bignum* exp, bignum* mod) {
	bignum* encoded;

	int len = src_len;
	int block_size = 0;
#if 0
	block_size = GetBlockSize(mod);
	int pck_num = ((len + block_size - 1) / block_size);
	int sz = pck_num * block_size;
#else
	block_size = BLOCK_SIZE_;
	int pck_num = ((len + BLOCK_SIZE_ - 1) / BLOCK_SIZE_);
	int sz = pck_num * BLOCK_SIZE_;
#endif 
	char* cpy = (char*)malloc(sz);
	memcpy(cpy, src, len);

	// zero padding to a multiple of bytes
	int i;
	for (i = len; i < sz; ++i) {
		cpy[i] = 0;
	}
	encoded = encodeMessage(sz, block_size, cpy, exp, mod);

	// here we only support to encrypt the first 94 bytes
	// because I don't have time to finish them all
	// so even "encoded" is a pointer to an array
	// we only translate the first element
	*des = bignum_tostring(encoded, des_len);

	bignum_deinit(encoded);
	free(cpy);
	// the return value is how many packet we got
	// return pck_num;
	return 1;
}

char* encodeStringChar(int *dest_len, char* src, int src_len, char* exp_, int exp_len, char* mod_, int mod_len) {
	bignum* exp = bignum_init();
	bignum_fromstring(exp, exp_, exp_len);
	bignum* mod = bignum_init();
	bignum_fromstring(mod, mod_, mod_len);

	bignum* encoded;

	int len = src_len;
	int block_size = 0;
#if 0
	block_size = GetBlockSize(mod);
	int pck_num = ((len + block_size - 1) / block_size);
	int sz = pck_num * block_size;
#else
	int pck_num = ((len + BLOCK_SIZE_ - 1) / BLOCK_SIZE_);
	int sz = pck_num * BLOCK_SIZE_;
#endif
	char* cpy = (char*)malloc(sz);
	memcpy(cpy, src, src_len);

	// zero padding to a multiple of bytes
	int i;
	for (i = len; i < sz; ++i) {
		cpy[i] = 0;
	}
	encoded = encodeMessage(sz, block_size, cpy, exp, mod);

	// here we only support to encrypt the first 94 bytes
	// because I don't have time to finish them all
	// so even "encoded" is a pointer to an array
	// we only translate the first element
	char* des = bignum_tostring(encoded, dest_len);

	// printf("============================== CDEBUG ===========================\n");
	// printf("src: %s\n", src);
	// printf("exp: %s\n", exp_);
	// printf("mod: %s\n", mod_);
	// printf("encode result: %s\n", des);
	// printf("============================== CDEBUG ===========================\n");

	bignum_deinit(encoded);
	bignum_deinit(exp);
	bignum_deinit(mod);
	free(cpy);
	// the return value is how many packet we got
	// return pck_num;
	return des;
}

char* encodeBytes(char* src, int len, int bytes, bignum* exp, bignum* mod) {
	int pck_num;
	int new_len = get_encode_info(len, bytes, &pck_num);
	char* new_src = (char*)malloc(new_len);
	memset(new_src, 0, new_len);
	memcpy(new_src, src, len);
	int i = 0;


	bignum* encoded = encodeMessage(new_len, bytes, new_src, exp, mod);


	word* ret = (word*)calloc(BLOCK_LENGTH * pck_num, sizeof(word));
	word* offset;
	for (i = 0; i < pck_num; ++i) {
		offset = ret + i * BLOCK_LENGTH;
		memcpy(offset, encoded[i].data, BLOCK_LENGTH * sizeof(word));
	}
	free(new_src);
	bignum_deinit(encoded);
	return (char*)ret;
}

char* encodeBytesChar(char* src, int len, int bytes, char* buf, char* exp_, int exp_len, char* mod_, int mod_len) {
	bignum* exp = bignum_init();
	bignum_fromstring(exp, exp_, exp_len);

	bignum* mod = bignum_init();
	bignum_fromstring(mod, mod_, mod_len);

	char* res = encodeBytes(src, len, bytes, exp, mod);

	int pck_num;
	get_encode_info(len, bytes, &pck_num);
	int res_len = pck_num * BLOCK_LENGTH * sizeof(word);
	memcpy(buf, res, res_len);
	free(res);

	// printf("============================== CDEBUG ===========================\n");
	// printf("src: %s\n", src);
	// printf("len: %d\n", len);
	// printf("bytes: %d\n", bytes);
	// printf("exp: %s\n", exp_);
	// printf("mod: %s\n", mod_);
	// printf("============================== CDEBUG ===========================\n");

	bignum_deinit(exp);
	bignum_deinit(mod);

	return res;
}

/**
* Decode the cryptogram of given length, using the private key (exponent, modulus)
* Each encrypted packet should represent "bytes" characters as per encodeMessage.
* The returned message will be of size len * bytes.
*/
char *decodeMessage(int len, int bytes, bignum *cryptogram, bignum *exponent, bignum *modulus) {
	unsigned char* decoded = (unsigned char*)malloc(len * bytes * sizeof(char));
	int i, j;
	bignum *x = bignum_init(), *remainder = bignum_init();
	bignum *num256 = bignum_init();
	bignum_fromint(num256, 256);
	for (i = 0; i < len; i++) {
		decode(&cryptogram[i], exponent, modulus, x);

		// printf("==================== DECRYPTED NOT DECODED ===================\n");
		// int k;
		// for (k = 0; k < x[0].length; ++k) {
		// 	printf("%u\n", x[0].data[k]);
		// }

		for (j = 0; j < bytes; j++) {
			bignum_idivider(x, num256, remainder);
			if (remainder->length == 0)
			{
				decoded[i*bytes + j] = '\0';
			}
			else
			{
				decoded[i*bytes + j] = (char)(remainder->data[0]);
			}
		}
	}
	return (char*)decoded;
}

int GetBlockSize(bignum* mod)
{
	int bytes = -1;
	bignum* shift = bignum_init();
	bignum* bbytes = bignum_init();
	bignum_fromint(shift, 1 << 7); /* 7 bits per char */
	bignum_fromint(bbytes, 1);
	while (bignum_less(bbytes, mod)) {
		bignum_imultiply(bbytes, shift); /* Shift by one byte, NB: we use bitmask representative so this can actually be a shift... */
		bytes++;
	}
	return bytes;
}

int decodeString(char* src, int src_len, char** des, int *des_len, bignum* exp, bignum* mod) {
	bignum* data = bignum_init();
	bignum_fromstring(data, src, src_len);
	int block_size = GetBlockSize(mod);
#if 0
	// similarly we decode the first block only
	*des = decodeMessage(src_len/ block_size, block_size, data, exp, mod);
#else	
	*des = decodeMessage(1, BLOCK_SIZE_ + 1, data, exp, mod);
#endif

	bignum_deinit(data);
	return 0;
}

char* decodeStringChar(char* src, int src_len, char* exp_,int exp_len, char* mod_, int mod_len) {
	bignum* data = bignum_init();
	bignum_fromstring(data, src, src_len);

	bignum* exp = bignum_init();
	bignum_fromstring(exp, exp_, exp_len);

	bignum* mod = bignum_init();
	bignum_fromstring(mod, mod_, mod_len);
#if 0
	int block_size = GetBlockSize(mod);
	// similarly we decode the first block only
	char* des = decodeMessage(src_len, block_size, data, exp, mod);
#else
	char* des = decodeMessage(1, BLOCK_SIZE_, data, exp, mod);
#endif

	// printf("============================== CDEBUG ===========================\n");
	// printf("src: %s\n", src);
	// printf("exp: %s\n", exp_);
	// printf("mod: %s\n", mod_);
	// printf("decode result: %s\n", des);
	// printf("============================== CDEBUG ===========================\n");

	bignum_deinit(data);
	bignum_deinit(exp);
	bignum_deinit(mod);

	return des;
}

char* decodeBytes(char* src, int len, int bytes, bignum* exp, bignum* mod) {
	word* real_data = (word*)src;
	// printf("byte length in decoding: %d\n", len);
	int pck_num;
	int last_length = get_decode_info(len, bytes, &pck_num);
	// printf("infered packet number in decode: %d\n", pck_num);

	bignum* gram = (bignum*)calloc(pck_num, sizeof(bignum));
	// printf("allocated memory\n");

	int i = 0;
	for (i = 0; i < pck_num; ++i) {
		gram[i].length = BLOCK_LENGTH;
		gram[i].capacity = BLOCK_LENGTH;
		gram[i].data = (word*)(real_data + BLOCK_LENGTH * i);
		// printf("%u\n", gram[i].data[0]);
	}
	gram[pck_num - 1].length = last_length;
	gram[pck_num - 1].capacity = last_length;

	// printf("========================== RAW RECEIVED ========================\n");
	// for (i = 0; i < gram[0].length; ++i) {
	// 	printf("%u\n", gram[0].data[i]);
	// }

	char* decoded = decodeMessage(pck_num, bytes, gram, exp, mod);

	free(gram);
	return decoded;
}

char* decodeBytesChar(char* src, int len, int bytes, char* buf, char* exp_, int exp_len, char* mod_, int mod_len) {
	bignum* exp = bignum_init();
	bignum_fromstring(exp, exp_, exp_len);

	bignum* mod = bignum_init();
	bignum_fromstring(mod, mod_, mod_len);

	char* res = decodeBytes(src, len, bytes, exp, mod);
	int pck_num = len / (sizeof(word) / sizeof(char)) / BLOCK_LENGTH;
	int decoded_len = pck_num * bytes;
	memcpy(buf, res, decoded_len);
	free(res);

	// printf("============================== CDEBUG ===========================\n");
	// printf("len: %d\n", len);
	// printf("bytes: %d\n", bytes);
	// printf("exp: %s\n", exp_);
	// printf("mod: %s\n", mod_);
	// printf("result: %s\n", res);
	// printf("============================== CDEBUG ===========================\n");

	bignum_deinit(exp);
	bignum_deinit(mod);

	return res;
}

void gen_rsa_key(bignum** pub_exp, bignum** pub_mod, bignum** priv_exp, bignum** priv_mod, int* bytes) {
	bignum *p = bignum_init(), *q = bignum_init(), *n = bignum_init();
	bignum *phi = bignum_init(), *e = bignum_init(), *d = bignum_init();
	bignum *temp1 = bignum_init(), *temp2 = bignum_init();
	bignum *bbytes = bignum_init(), *shift = bignum_init();

	*pub_exp = bignum_init();
	*pub_mod = bignum_init();
	*priv_exp = bignum_init();
	*priv_mod = bignum_init();

	randPrime(FACTOR_DIGITS, p);
	// printf("Got first prime factor\n");

	randPrime(FACTOR_DIGITS, q);
	// printf("Got second prime factor\n");

	bignum_multiply(n, p, q);
	// printf("Got modulus\n");

	bignum_subtract(temp1, p, &NUMS[1]);
	bignum_subtract(temp2, q, &NUMS[1]);
	bignum_multiply(phi, temp1, temp2); /* phi = (p - 1) * (q - 1) */
										// printf("Got totient\n");

	randExponent(phi, EXPONENT_MAX, e);
	// printf("Chose public exponent\n");
	// printf("Got public key\n");
	bignum_copy(e, *pub_exp);
	bignum_copy(n, *pub_mod);

	bignum_inverse(e, phi, d);

	// printf("Got private key\n");
	bignum_copy(d, *priv_exp);
	bignum_copy(n, *priv_mod);

	*bytes = -1;
	bignum_fromint(shift, 1 << 8);
	bignum_fromint(bbytes, 1);
	while (bignum_less(bbytes, n)) {
		bignum_imultiply(bbytes, shift);
		(*bytes)++;
	}

	bignum_deinit(p);
	bignum_deinit(q);
	bignum_deinit(n);
	bignum_deinit(phi);
	bignum_deinit(e);
	bignum_deinit(d);
	bignum_deinit(bbytes);
	bignum_deinit(shift);
	bignum_deinit(temp1);
	bignum_deinit(temp2);
}

int get_encode_info(int len, int bytes, int* pck_num) {
	*pck_num = (len + bytes - 1) / bytes;
	return (*pck_num * bytes);
}

int get_decode_info(int len, int bytes, int* pck_num) {
	int block_length = (sizeof(int) / sizeof(char)) * BLOCK_LENGTH;
	*pck_num = (len + block_length - 1) / block_length;
	return (block_length - (*pck_num * block_length - len)) / (sizeof(int) / sizeof(char));
}

// ============================================================================



/**
* Initialize a bignum structure. This is the only way to safely create a bignum
* and should be called where-ever one is declared. (We realloc the memory in all
* other cases which is technically safe but may cause problems when we go to free
* it.)
*/
bignum* bignum_init() {
	bignum* b = malloc(sizeof(bignum));
	b->length = 0;
	b->capacity = BIGNUM_CAPACITY;
	b->data = calloc(BIGNUM_CAPACITY, sizeof(word));
	return b;
}

/**
* Free resources used by a bignum. Use judiciously to avoid memory leaks.
*/
void bignum_deinit(bignum* b) {
	free(b->data);
	free(b);
}

/**
* Check if the given bignum is zero
*/
int bignum_iszero(bignum* b) {
	return b->length == 0 || (b->length == 1 && b->data[0] == 0);
}

/**
* Check if the given bignum is nonzero.
*/
int bignum_isnonzero(bignum* b) {
	return !bignum_iszero(b);
}

/**
* Copy from source bignum into destination bignum.
*/
void bignum_copy(bignum* source, bignum* dest) {
	dest->length = source->length;
	if (source->capacity > dest->capacity) {
		dest->capacity = source->capacity;
		dest->data = realloc(dest->data, dest->capacity * sizeof(word));
	}
	memcpy(dest->data, source->data, dest->length * sizeof(word));
}

/**
* Load a bignum from a base 10 string. Only pure numeric strings will work.
*/
int bignum_fromstring(bignum* b, char* string, int len) {
	int i;
	/*!可能字符串中包含结束符*/
	//while (string[len] != '\0') len++; /* Find string length */
	int index = 0;
	for (i = 0; i < len; i++) {
		if (i != 0) bignum_imultiply(b, &NUMS[10]); /* Base 10 multiply */
		if (string[i] >= '0' && string[i] <=  '9')
		{
			index = string[i] - '0';
		}
		else
		{
			//不是16进制数据
			return 0;
		}
		bignum_iadd(b, &NUMS[index]); /* Add */
	}
	return 1;
}

/**
* Load a bignum from a base 16 string. Only pure numeric strings will work.
*/
int bignum_fromhexstring(bignum* b, char* string, int len) {
	int i;
	/*!可能字符串中包含结束符*/
	//while (string[len] != '\0') len++; /* Find string length */
	int index = 0;
	for (i = 0; i < len; i++) {
		if (i != 0) bignum_imultiply(b, &NUMS[16]); /* Base 10 multiply */
		if (string[i] == 'a'|| string[i] == 'A')
		{
			index = 10;
		}else if (string[i] == 'b' || string[i] == 'B')
		{
			index = 11;
		}
		else if (string[i] == 'c' || string[i] == 'C')
		{
			index = 12;
		}
		else if (string[i] == 'd' || string[i] == 'd')
		{
			index = 13;
		}
		else if (string[i] == 'e' || string[i] == 'E')
		{
			index = 14;
		}
		else if (string[i] == 'f' || string[i] == 'F')
		{
			index = 15;
		}
		else if (string[i] >='0' && string[i] <= '9')
		{
			index = string[i] - '0';
		}
		else
		{
			//不是16进制数据
			return 0;
		}
		bignum_iadd(b, &NUMS[index]); /* Add */
	}
	return 1;
}

/**
* Load a bignum from an unsigned integer.
*/
void bignum_fromint(bignum* b, unsigned int num) {
	b->length = 1;
	if (b->capacity < b->length) {
		b->capacity = b->length;
		b->data = realloc(b->data, b->capacity * sizeof(word));
	}
	b->data[0] = num;
}

/**
* Print a bignum to stdout as base 10 integer. This is done by
* repeated division by 10. We can make it more efficient by dividing by
* 10^9 for example, then doing single precision arithmetic to retrieve the
* 9 remainders
*/
void bignum_print(bignum* b) {
	int cap = 100, len = 0, i;
	char* buffer = malloc(cap * sizeof(char));
	bignum *copy = bignum_init(), *remainder = bignum_init();
	if (b->length == 0 || bignum_iszero(b)) printf("0");
	else {
		bignum_copy(b, copy);
		while (bignum_isnonzero(copy)) {
			bignum_idivider(copy, &NUMS[10], remainder);
			buffer[len++] = (char)remainder->data[0];
			if (len >= cap) {
				cap *= 2;
				buffer = realloc(buffer, cap * sizeof(char));
			}
		}
		for (i = len - 1; i >= 0; i--) printf("%d", buffer[i]);
	}
	bignum_deinit(copy);
	bignum_deinit(remainder);
	free(buffer);
}

char itoc(char i) {
	return '0' + i;
}

void str_inverse(char* str) {
	char temp;
	int i;
	int len = strlen(str);
	for (i = 0; i < len / 2; i++) {
		temp = *(str + i);
		*(str + i) = *(str + len - i - 1);
		*(str + len - 1 - i) = temp;
	}
}

/**
* the returned buffer should be freed later
*/
char* bignum_tostring(bignum* b, int *pLen) {
	int cap = 100, len = 0, i;
	char* buffer = malloc(cap * sizeof(char));
	bignum *copy = bignum_init(), *remainder = bignum_init();
	if (b->length == 0 || bignum_iszero(b)) buffer[0] = '0';
	else {
		bignum_copy(b, copy);
		while (bignum_isnonzero(copy)) {
			bignum_idivider(copy, &NUMS[10], remainder);
			buffer[len++] = (char)remainder->data[0];
			if (len >= cap) {
				cap *= 2;
				buffer = realloc(buffer, cap * sizeof(char));
			}
		}
		for (i = len - 1; i >= 0; i--) buffer[i] = itoc(buffer[i]);
	}
	buffer[len] = '\0';
	/*返回字符串长度*/
	*pLen = len;
	str_inverse(buffer);
	bignum_deinit(copy);
	bignum_deinit(remainder);
	return buffer;
}

/**
* Check if two bignums are equal.
*/
int bignum_equal(bignum* b1, bignum* b2) {
	int i;
	if (bignum_iszero(b1) && bignum_iszero(b2)) return 1;
	else if (bignum_iszero(b1)) return 0;
	else if (bignum_iszero(b2)) return 0;
	else if (b1->length != b2->length) return 0;
	for (i = b1->length - 1; i >= 0; i--) {
		if (b1->data[i] != b2->data[i]) return 0;
	}
	return 1;
}

/**
* Check if bignum b1 is greater than b2
*/
int bignum_greater(bignum* b1, bignum* b2) {
	int i;
	if (bignum_iszero(b1) && bignum_iszero(b2)) return 0;
	else if (bignum_iszero(b1)) return 0;
	else if (bignum_iszero(b2)) return 1;
	else if (b1->length != b2->length) return b1->length > b2->length;
	for (i = b1->length - 1; i >= 0; i--) {
		if (b1->data[i] != b2->data[i]) return b1->data[i] > b2->data[i];
	}
	return 0;
}

/**
* Check if bignum b1 is less than b2
*/
int bignum_less(bignum* b1, bignum* b2) {
	int i;
	if (bignum_iszero(b1) && bignum_iszero(b2)) return 0;
	else if (bignum_iszero(b1)) return 1;
	else if (bignum_iszero(b2)) return 0;
	else if (b1->length != b2->length) return b1->length < b2->length;
	for (i = b1->length - 1; i >= 0; i--) {
		if (b1->data[i] != b2->data[i]) return b1->data[i] < b2->data[i];
	}
	return 0;
}

/**
* Check if bignum b1 is greater than or equal to b2
*/
int bignum_geq(bignum* b1, bignum* b2) {
	return !bignum_less(b1, b2);
}

/**
* Check if bignum b1 is less than or equal to b2
*/
int bignum_leq(bignum* b1, bignum* b2) {
	return !bignum_greater(b1, b2);
}

/**
* Perform an in place add into the source bignum. That is source += add
*/
void bignum_iadd(bignum* source, bignum* add) {
	bignum* temp = bignum_init();
	bignum_add(temp, source, add);
	bignum_copy(temp, source);
	bignum_deinit(temp);
}

/**
* Add two bignums by the add with carry method. result = b1 + b2
*/
void bignum_add(bignum* result, bignum* b1, bignum* b2) {
	word sum, carry = 0;
	int i, n = MAX(b1->length, b2->length);
	if (n + 1 > result->capacity) {
		result->capacity = n + 1;
		result->data = realloc(result->data, result->capacity * sizeof(word));
	}
	for (i = 0; i < n; i++) {
		sum = carry;
		if (i < b1->length) sum += b1->data[i];
		if (i < b2->length) sum += b2->data[i];
		result->data[i] = sum; /* Already taken mod 2^32 by unsigned wrap around */

		if (i < b1->length) {
			if (sum < b1->data[i]) carry = 1; /* Result must have wrapped 2^32 so carry bit is 1 */
			else carry = 0;
		}
		else {
			if (sum < b2->data[i]) carry = 1; /* Result must have wrapped 2^32 so carry bit is 1 */
			else carry = 0;
		}
	}
	if (carry == 1) {
		result->length = n + 1;
		result->data[n] = 1;
	}
	else {
		result->length = n;
	}
}

/**
* Perform an in place subtract from the source bignum. That is, source -= sub
*/
void bignum_isubtract(bignum* source, bignum* sub) {
	bignum* temp = bignum_init();
	bignum_subtract(temp, source, sub);
	bignum_copy(temp, source);
	bignum_deinit(temp);
}

/**
* Subtract bignum b2 from b1. result = b1 - b2. The result is undefined if b2 > b1.
* This uses the basic subtract with carry method
*/
void bignum_subtract(bignum* result, bignum* b1, bignum* b2) {
	int length = 0, i;
	word carry = 0, diff, temp;
	if (b1->length > result->capacity) {
		result->capacity = b1->length;
		result->data = realloc(result->data, result->capacity * sizeof(word));
	}
	for (i = 0; i < b1->length; i++) {
		temp = carry;
		if (i < b2->length) temp = temp + b2->data[i]; /* Auto wrapped mod RADIX */
		diff = b1->data[i] - temp;
		if (temp > b1->data[i]) carry = 1;
		else carry = 0;
		result->data[i] = diff;
		if (result->data[i] != 0) length = i + 1;
	}
	result->length = length;
}

/**
* Perform an in place multiplication into the source bignum. That is source *= mult
*/
void bignum_imultiply(bignum* source, bignum* mult) {
	bignum* temp = bignum_init();
	bignum_multiply(temp, source, mult);
	bignum_copy(temp, source);
	bignum_deinit(temp);
}

/**
* Multiply two bignums by the naive school method. result = b1 * b2. I have experimented
* with FFT mult and Karatsuba but neither was looking to be  more efficient than the school
* method for reasonable number of digits. There are some improvments to be made here,
* especially for squaring which can cut out half of the operations.
*/
void bignum_multiply(bignum* result, bignum* b1, bignum* b2) {
	int i, j, k;
	word carry, temp;
	unsigned long long int prod; /* Long for intermediate product this is not portable and should probably be changed */
	if (b1->length + b2->length > result->capacity) {
		result->capacity = b1->length + b2->length;
		result->data = realloc(result->data, result->capacity * sizeof(word));
	}
	for (i = 0; i < b1->length + b2->length; i++) result->data[i] = 0;

	for (i = 0; i < b1->length; i++) {
		for (j = 0; j < b2->length; j++) {
			prod = (b1->data[i] * (unsigned long long int)b2->data[j]) + (unsigned long long int)(result->data[i + j]); /* This should not overflow... */
			carry = (word)(prod / RADIX);

			/* Add carry to the next word over, but this may cause further overflow.. propogate */
			k = 1;
			while (carry > 0) {
				temp = result->data[i + j + k] + carry;
				if (temp < result->data[i + j + k]) carry = 1;
				else carry = 0;
				result->data[i + j + k] = temp; /* Already wrapped in unsigned arithmetic */
				k++;
			}

			prod = (result->data[i + j] + b1->data[i] * (unsigned long long int)b2->data[j]) % RADIX; /* Again, should not overflow... */
			result->data[i + j] = (word)prod; /* Add */
		}
	}
	if (b1->length + b2->length > 0 && result->data[b1->length + b2->length - 1] == 0) result->length = b1->length + b2->length - 1;
	else result->length = b1->length + b2->length;
}

/**
* Perform an in place divide of source. source = source/div.
*/
void bignum_idivide(bignum *source, bignum *div) {
	bignum *q = bignum_init(), *r = bignum_init();
	bignum_divide(q, r, source, div);
	bignum_copy(q, source);
	bignum_deinit(q);
	bignum_deinit(r);
}

/**
* Perform an in place divide of source, also producing a remainder.
* source = source/div and remainder = source - source/div.
*/
void bignum_idivider(bignum* source, bignum* div, bignum* remainder) {
	bignum *q = bignum_init(), *r = bignum_init();
	bignum_divide(q, r, source, div);
	bignum_copy(q, source);
	bignum_copy(r, remainder);
	bignum_deinit(q);
	bignum_deinit(r);
}

/**
* Calculate the remainder when source is divided by div.
*/
void bignum_remainder(bignum* source, bignum *div, bignum* remainder) {
	bignum *q = bignum_init();
	bignum_divide(q, remainder, source, div);
	bignum_deinit(q);
}

/**
* Modulate the source by the modulus. source = source % modulus
*/
void bignum_imodulate(bignum* source, bignum* modulus) {
	bignum *q = bignum_init(), *r = bignum_init();
	bignum_divide(q, r, source, modulus);
	bignum_copy(r, source);
	bignum_deinit(q);
	bignum_deinit(r);
}

/**
* Divide two bignums by naive long division, producing both a quotient and remainder.
* quotient = floor(b1/b2), remainder = b1 - quotient * b2. If b1 < b2 the quotient is
* trivially 0 and remainder is b2.
*/
void bignum_divide(bignum* quotient, bignum* remainder, bignum* b1, bignum* b2) {
	bignum *b2copy = bignum_init(), *b1copy = bignum_init();
	bignum *temp = bignum_init(), *temp2 = bignum_init(), *temp3 = bignum_init();
	bignum* quottemp = bignum_init();
	word carry = 0;
	int n, m, i, j, length = 0;
	unsigned long long factor = 1;
	unsigned long long gquot, gtemp, grem;
	if (bignum_less(b1, b2)) { /* Trivial case, b1/b2 = 0 iff b1 < b2. */
		quotient->length = 0;
		bignum_copy(b1, remainder);
	}
	else if (bignum_iszero(b1)) { /* 0/x = 0.. assuming b2 is nonzero */
		quotient->length = 0;
		bignum_fromint(remainder, 0);
	}
	else if (b2->length == 1) { /* Division by a single limb means we can do simple division */
		if (quotient->capacity < b1->length) {
			quotient->capacity = b1->length;
			quotient->data = realloc(quotient->data, quotient->capacity * sizeof(word));
		}
		for (i = b1->length - 1; i >= 0; i--) {
			gtemp = carry * RADIX + b1->data[i];
			gquot = gtemp / b2->data[0];
			quotient->data[i] = (word)gquot;
			if (quotient->data[i] != 0 && length == 0) length = i + 1;
			carry = gtemp % b2->data[0];
		}
		bignum_fromint(remainder, carry);
		quotient->length = length;
	}
	else { /* Long division is neccessary */
		n = b1->length + 1;
		m = b2->length;
		if (quotient->capacity < n - m) {
			quotient->capacity = n - m;
			quotient->data = realloc(quotient->data, (n - m) * sizeof(word));
		}
		bignum_copy(b1, b1copy);
		bignum_copy(b2, b2copy);
		/* Normalize.. multiply by the divisor by 2 until MSB >= HALFRADIX. This ensures fast
		* convergence when guessing the quotient below. We also multiply the dividend by the
		* same amount to ensure the result does not change. */
		while (b2copy->data[b2copy->length - 1] < HALFRADIX) {
			factor *= 2;
			bignum_imultiply(b2copy, &NUMS[2]);
		}
		if (factor > 1) {
			bignum_fromint(temp, (word)factor);
			bignum_imultiply(b1copy, temp);
		}
		/* Ensure the dividend is longer than the original (pre-normalized) divisor. If it is not
		* we introduce a dummy zero word to artificially inflate it. */
		if (b1copy->length != n) {
			b1copy->length++;
			if (b1copy->length > b1copy->capacity) {
				b1copy->capacity = b1copy->length;
				b1copy->data = realloc(b1copy->data, b1copy->capacity * sizeof(word));
			}
			b1copy->data[n - 1] = 0;
		}

		/* Process quotient by long division */
		for (i = n - m - 1; i >= 0; i--) {
			gtemp = RADIX * b1copy->data[i + m] + b1copy->data[i + m - 1];
			gquot = gtemp / b2copy->data[m - 1];
			if (gquot >= RADIX) gquot = UINT_MAX;
			grem = gtemp % b2copy->data[m - 1];
			while (grem < RADIX && gquot * b2copy->data[m - 2] > RADIX * grem + b1copy->data[i + m - 2]) { /* Should not overflow... ? */
				gquot--;
				grem += b2copy->data[m - 1];
			}
			quottemp->data[0] = gquot % RADIX;
			quottemp->data[1] = (word)(gquot / RADIX);
			if (quottemp->data[1] != 0) quottemp->length = 2;
			else quottemp->length = 1;
			bignum_multiply(temp2, b2copy, quottemp);
			if (m + 1 > temp3->capacity) {
				temp3->capacity = m + 1;
				temp3->data = realloc(temp3->data, temp3->capacity * sizeof(word));
			}
			temp3->length = 0;
			for (j = 0; j <= m; j++) {
				temp3->data[j] = b1copy->data[i + j];
				if (temp3->data[j] != 0) temp3->length = j + 1;
			}
			if (bignum_less(temp3, temp2)) {
				bignum_iadd(temp3, b2copy);
				gquot--;
			}
			bignum_isubtract(temp3, temp2);
			for (j = 0; j < temp3->length; j++) b1copy->data[i + j] = temp3->data[j];
			for (j = temp3->length; j <= m; j++) b1copy->data[i + j] = 0;
			quotient->data[i] = (word)gquot;
			if (quotient->data[i] != 0) quotient->length = i;
		}

		if (quotient->data[b1->length - b2->length] == 0) quotient->length = b1->length - b2->length;
		else quotient->length = b1->length - b2->length + 1;

		/* Divide by factor now to find final remainder */
		carry = 0;
		for (i = b1copy->length - 1; i >= 0; i--) {
			gtemp = carry * RADIX + b1copy->data[i];
			b1copy->data[i] = (word)(gtemp / factor);
			if (b1copy->data[i] != 0 && length == 0) length = i + 1;
			carry = (word)(gtemp % factor);
		}
		b1copy->length = length;
		bignum_copy(b1copy, remainder);
	}
	bignum_deinit(temp);
	bignum_deinit(temp2);
	bignum_deinit(temp3);
	bignum_deinit(b1copy);
	bignum_deinit(b2copy);
	bignum_deinit(quottemp);
}

/**
* Perform modular exponentiation by repeated squaring. This will compute
* result = base^exponent mod modulus
*/
void bignum_modpow(bignum* base, bignum* exponent, bignum* modulus, bignum* result) {
	bignum *a = bignum_init(), *b = bignum_init(), *c = bignum_init();
	bignum *discard = bignum_init(), *remainder = bignum_init();
	bignum_copy(base, a);
	bignum_copy(exponent, b);
	bignum_copy(modulus, c);
	bignum_fromint(result, 1);
	while (bignum_greater(b, &NUMS[0])) {
		if (b->data[0] & 1) {
			bignum_imultiply(result, a);
			bignum_imodulate(result, c);
		}
		bignum_idivide(b, &NUMS[2]);
		bignum_copy(a, discard);
		bignum_imultiply(a, discard);
		bignum_imodulate(a, c);
	}
	bignum_deinit(a);
	bignum_deinit(b);
	bignum_deinit(c);
	bignum_deinit(discard);
	bignum_deinit(remainder);
}

/**
* Compute the gcd of two bignums. result = gcd(b1, b2)
*/
void bignum_gcd(bignum* b1, bignum* b2, bignum* result) {
	bignum *a = bignum_init(), *b = bignum_init(), *remainder = bignum_init();
	bignum *temp = bignum_init(), *discard = bignum_init();
	bignum_copy(b1, a);
	bignum_copy(b2, b);
	while (!bignum_equal(b, &NUMS[0])) {
		bignum_copy(b, temp);
		bignum_imodulate(a, b);
		bignum_copy(a, b);
		bignum_copy(temp, a);
	}
	bignum_copy(a, result);
	bignum_deinit(a);
	bignum_deinit(b);
	bignum_deinit(remainder);
	bignum_deinit(temp);
	bignum_deinit(discard);
}

/**
* Compute the inverse of a mod m. Or, result = a^-1 mod m.
*/
void bignum_inverse(bignum* a, bignum* m, bignum* result) {
	bignum *remprev = bignum_init(), *rem = bignum_init();
	bignum *auxprev = bignum_init(), *aux = bignum_init();
	bignum *rcur = bignum_init(), *qcur = bignum_init(), *acur = bignum_init();

	bignum_copy(m, remprev);
	bignum_copy(a, rem);
	bignum_fromint(auxprev, 0);
	bignum_fromint(aux, 1);
	while (bignum_greater(rem, &NUMS[1])) {
		bignum_divide(qcur, rcur, remprev, rem);
		/* Observe we are finding the inverse in a finite field so we can use
		* a modified algorithm that avoids negative numbers here */
		bignum_subtract(acur, m, qcur);
		bignum_imultiply(acur, aux);
		bignum_iadd(acur, auxprev);
		bignum_imodulate(acur, m);

		bignum_copy(rem, remprev);
		bignum_copy(aux, auxprev);
		bignum_copy(rcur, rem);
		bignum_copy(acur, aux);
	}

	bignum_copy(acur, result);

	bignum_deinit(remprev);
	bignum_deinit(rem);
	bignum_deinit(auxprev);
	bignum_deinit(aux);
	bignum_deinit(rcur);
	bignum_deinit(qcur);
	bignum_deinit(acur);
}

/**
* Compute the jacobi symbol, J(ac, nc).
*/
int bignum_jacobi(bignum* ac, bignum* nc) {
	bignum *remainder = bignum_init(), *twos = bignum_init();
	bignum *temp = bignum_init(), *a = bignum_init(), *n = bignum_init();
	int mult = 1, result = 0;
	bignum_copy(ac, a);
	bignum_copy(nc, n);
	while (bignum_greater(a, &NUMS[1]) && !bignum_equal(a, n)) {
		bignum_imodulate(a, n);
		if (bignum_leq(a, &NUMS[1]) || bignum_equal(a, n)) break;
		bignum_fromint(twos, 0);
		/* Factor out multiples of two */
		while (a->data[0] % 2 == 0) {
			bignum_iadd(twos, &NUMS[1]);
			bignum_idivide(a, &NUMS[2]);
		}
		/* Coefficient for flipping */
		if (bignum_greater(twos, &NUMS[0]) && twos->data[0] % 2 == 1) {
			bignum_remainder(n, &NUMS[8], remainder);
			if (!bignum_equal(remainder, &NUMS[1]) && !bignum_equal(remainder, &NUMS[7])) {
				mult *= -1;
			}
		}
		if (bignum_leq(a, &NUMS[1]) || bignum_equal(a, n)) break;
		bignum_remainder(n, &NUMS[4], remainder);
		bignum_remainder(a, &NUMS[4], temp);
		if (!bignum_equal(remainder, &NUMS[1]) && !bignum_equal(temp, &NUMS[1])) mult *= -1;
		bignum_copy(a, temp);
		bignum_copy(n, a);
		bignum_copy(temp, n);
	}
	if (bignum_equal(a, &NUMS[1])) result = mult;
	else result = 0;
	bignum_deinit(remainder);
	bignum_deinit(twos);
	bignum_deinit(temp);
	bignum_deinit(a);
	bignum_deinit(n);
	return result;
}

/**
* Check whether a is a Euler witness for n. That is, if a^(n - 1)/2 != Ja(a, n) mod n
*/
int solovayPrime(int a, bignum* n) {
	bignum *ab = bignum_init(), *res = bignum_init(), *pow = bignum_init();
	bignum *modpow = bignum_init();
	int x, result;

	bignum_fromint(ab, a);
	x = bignum_jacobi(ab, n);
	if (x == -1) bignum_subtract(res, n, &NUMS[1]);
	else bignum_fromint(res, x);
	bignum_copy(n, pow);
	bignum_isubtract(pow, &NUMS[1]);
	bignum_idivide(pow, &NUMS[2]);
	bignum_modpow(ab, pow, n, modpow);

	result = !bignum_equal(res, &NUMS[0]) && bignum_equal(modpow, res);
	bignum_deinit(ab);
	bignum_deinit(res);
	bignum_deinit(pow);
	bignum_deinit(modpow);
	return result;
}

/**
* Test if n is probably prime, by repeatedly using the Solovay-Strassen primality test.
*/
int probablePrime(bignum* n, int k) {
	if (bignum_equal(n, &NUMS[2])) return 1;
	else if (n->data[0] % 2 == 0 || bignum_equal(n, &NUMS[1])) return 0;
	while (k-- > 0) {
		if (n->length <= 1) { /* Prevent a > n */
			if (!solovayPrime(rand() % (n->data[0] - 2) + 2, n)) return 0;
		}
		else {
			int wit = rand() % (RAND_MAX - 2) + 2;
			if (!solovayPrime(wit, n)) return 0;
		}
	}
	return 1;
}

/**
* Generate a random prime number, with a specified number of digits.
* This will generate a base 10 digit string of given length, convert it
* to a bignum and then do an increasing search for the first probable prime.
*/
void randPrime(int numDigits, bignum* result) {
	char *string = malloc((numDigits + 1) * sizeof(char));
	int i;
	string[0] = (rand() % 9) + '1'; /* No leading zeros */
	string[numDigits - 1] = (rand() % 5) * 2 + '1'; /* Last digit is odd */
	for (i = 1; i < numDigits - 1; i++) string[i] = (rand() % 10) + '0';
	string[numDigits] = '\0';
	bignum_fromstring(result, string, numDigits);
	while (1) {
		if (probablePrime(result, ACCURACY)) {
			free(string);
			return;
		}
		bignum_iadd(result, &NUMS[2]); /* result += 2 */
	}
}

/**
* Choose a random public key exponent for the RSA algorithm. The exponent will
* be less than the modulus, n, and coprime to phi.
*/
void randExponent(bignum* phi, int n, bignum* result) {
	bignum* gcd = bignum_init();
	int e = rand() % n;
	while (1) {
		bignum_fromint(result, e);
		bignum_gcd(result, phi, gcd);
		if (bignum_equal(gcd, &NUMS[1])) {
			bignum_deinit(gcd);
			return;
		}
		e = (e + 1) % n;
		if (e <= 2) e = 3;
	}
}

/**
* Read the file fd into an array of bytes ready for encryption.
* The array will be padded with zeros until it divides the number of
* bytes encrypted per block. Returns the number of bytes read.
*/
int readFile(FILE* fd, char** buffer, int bytes) {
	int len = 0, cap = BUF_SIZE, r;
	char buf[BUF_SIZE];
	*buffer = malloc(BUF_SIZE * sizeof(char));
	while ((r = fread(buf, sizeof(char), BUF_SIZE, fd)) > 0) {
		if (len + r >= cap) {
			cap *= 2;
			*buffer = realloc(*buffer, cap);
		}
		memcpy(&(*buffer)[len], buf, r);
		len += r;
	}
	/* Pad the last block with zeros to signal end of cryptogram. An additional block is added if there is no room */
	if (len + bytes - len % bytes > cap) *buffer = realloc(*buffer, len + bytes - len % bytes);
	do {
		(*buffer)[len] = '\0';
		len++;
	} while (len % bytes != 0);
	return len;
}

/**
* Encode the message m using public exponent and modulus, result = m^e mod n
*/
void encode(bignum* m, bignum* e, bignum* n, bignum* result) {
	bignum_modpow(m, e, n, result);
}

/**
* Decode cryptogram c using private exponent and public modulus, result = c^d mod n
*/
void decode(bignum* c, bignum* d, bignum* n, bignum* result) {
	bignum_modpow(c, d, n, result);
}
#elif defined(RSA2)

#include "rsa.h"


int rsa1024(uint64_t res[], uint64_t data[], uint64_t expo[], uint64_t key[])
{
	int32_t i, j, expo_len;
	uint64_t mod_data[18] = { 0 }, result[18] = { 0 };
	uint64_t temp_expo = 0;

	modbignum(mod_data, data, key, 16);
	result[0] = 1;
	expo_len = bit_length(expo, 16) / 64;
	for (i = 0; i<expo_len + 1; i++)
	{
		temp_expo = expo[i];
		for (j = 0; j<64; j++)
		{
			if (temp_expo & 0x1UL)
				modmult1024(result, result, mod_data, key);

			modmult1024(mod_data, mod_data, mod_data, key);
			temp_expo = temp_expo >> 1;
		}
	}
	for (i = 0; i<16; i++)
		res[i] = result[i];

	char *p = (char*)res;
	for (i = 16 * 8 -1; i >= 0; i--)
	{
		if ((int)p[i] != 0)
		{
			return i+1;
		}
	}
	return 0;
}




bool addbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n)
{
	uint32_t i;
	uint64_t j, k, carry = 0;
	for (i = 0; i<n; i++)
	{
		j = (op1[i] & 0xffffffff) + (op2[i] & 0xffffffff) + carry;

		k = ((op1[i] >> 32) & 0xffffffff) + ((op2[i] >> 32) & 0xffffffff) + ((j >> 32) & 0xffffffff);

		carry = ((k >> 32) & 0xffffffff);

		res[i] = ((k & 0xffffffff) << 32) | (j & 0xffffffff);
	}
	res[i] = carry;
	return 0;
}

bool multbignum(uint64_t res[], uint64_t op1[], uint32_t op2, uint32_t n)
{
	uint32_t i;
	uint64_t j, k, carry1 = 0, carry2 = 0;
	for (i = 0; i<n; i++)
	{
		j = (op1[i] & 0xffffffff) * (op2 & 0xffffffff);

		k = ((op1[i] >> 32) & 0xffffffff) * (op2 & 0xffffffff);
		carry1 = ((k >> 32) & 0xffffffff);
		k = (k & 0xffffffff) + ((j >> 32) & 0xffffffff);
		j = (j & 0xffffffff) + carry2;
		k = k + ((j >> 32) & 0xffffffff);
		carry2 = carry1 + ((k >> 32) & 0xffffffff);

		res[i] = ((k & 0xffffffff) << 32) | (j & 0xffffffff);
	}
	res[i] = carry2;
	return 0;
}
bool modmult1024(uint64_t res[], uint64_t op1[], uint64_t op2[], uint64_t mod[]) //optimized
{
	int32_t i, j;
	uint64_t mult1[33] = { 0 }, mult2[33] = { 0 },
		result[33] = { 0 }, xmod[33] = { 0 };

	for (i = 0; i<16; i++)
		xmod[i] = mod[i];

	for (i = 0; i<16; i++)
	{
		for (j = 0; j<33; j++)
		{
			mult1[j] = 0;
			mult2[j] = 0;
		}
		multbignum(mult1, op1, (op2[i] & 0xffffffff), 16);
		multbignum(mult2, op1, ((op2[i] >> 32) & 0xffffffff), 16);
		slnbignum(mult2, mult2, 33, 32);
		addbignum(mult2, mult2, mult1, 32);

		slnbignum(mult2, mult2, 33, 64 * i);

		addbignum(result, result, mult2, 32);

	}
	modbignum(result, result, xmod, 33);
	for (i = 0; i<16; i++)
		res[i] = result[i];

	return 0;
}
/*
bool modmult1024(uint64_t res[], uint64_t op1[], uint64_t op2[],uint64_t mod[])
{
int32_t i,j;
uint64_t mult1[19]={0},mult2[19]={0},result[18]={0};
for(i=0;i<16;i++)
{
multbignum(mult1,op1,(op2[i]&0xffffffff),16);
multbignum(mult2,op1,((op2[i]>>32)&0xffffffff),16);
slnbignum(mult2,mult2,17,32);
addbignum(mult2,mult2,mult1,17);
modbignum(mult2,mult2,mod,17);
for(j=0;j<i;j++)
{
slnbignum(mult2,mult2,17,64);
modbignum(mult2,mult2,mod,17);
}

addbignum(result,result,mult2,16);
modbignum(result,result,mod,17);

}
for(i=0;i<16;i++)
res[i]=result[i];

return 0;
}
*/
bool modbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n)//optimized
{
	uint32_t i;
	int32_t len_op1, len_op2, len_dif;

	len_op1 = bit_length(op1, n);
	len_op2 = bit_length(op2, n);
	len_dif = len_op1 - len_op2;



	for (i = 0; i<n; i++)
		res[i] = op1[i];

	if (len_dif < 0)
	{
		return 1;
	}

	if (len_dif == 0)
	{
		while (compare(res, op2, n) >= 0)
		{
			subbignum(res, res, op2, n);
		}
		return 1;
	}

	slnbignum(op2, op2, n, len_dif);
	for (i = 0; i<len_dif; i++)
	{
		srnbignum(op2, op2, n, 1);
		while (compare(res, op2, n) >= 0)
		{
			subbignum(res, res, op2, n);
		}
	}

	return 1;
}

/*
bool modbignum(uint64_t res[],uint64_t op1[], uint64_t op2[],uint32_t n)
{
uint32_t i;
int32_t len_op1,len_op2,len_dif;

len_op1 = bit_length(op1,n);
len_op2 = bit_length(op2,n);
len_dif = len_op1 - len_op2;

for(i=0;i<n;i++)
res[i]=op1[i];

if(len_dif < 0)
{
return 1;
}
if(len_dif == 0)
{
modnum(res,res,op2,n);
return 1;
}

slnbignum(op2,op2,n,len_dif);
for(i=0;i<len_dif;i++)
{
srnbignum(op2,op2,n,1);
modnum(res,res,op2,n);
}
return 1;
}
*/
/****************************************************************
* bool modnum(uint64_t res[],uint64_t op1[], uint64_t op2[],uint32_t n)
* res = op1 % op2
* n is bit length/64
* res must have extra 64 bits to avoid errors
****************************************************************/
bool modnum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n)
{
	uint32_t i;
	bool result = 0;
	for (i = 0; i<n; i++)
		res[i] = op1[i];

	while (!result)
	{
		result = subbignum(res, res, op2, n);
	}

	addbignum(res, res, op2, n);
	res[n] = 0;

	return 0;
}
/****************************************************************
* int32_t compare(uint64_t op1[], uint64_t op2[],uint32_t n)
* returns 1 if op1>op2
* 		 -1 if op1<op2
* 		  0 if op1=op2
*****************************************************************/
int32_t compare(uint64_t op1[], uint64_t op2[], uint32_t n)
{
	for (; n>0; n--)
	{
		if (op1[n - 1]>op2[n - 1])
		{
			return 1;
		}
		else if (op1[n - 1]<op2[n - 1])
		{
			return -1;
		}
	}

	return 0;
}

/****************************************************************
* bool subbignum(uint64_t res[], uint64_t op1[], uint64_t op2[],uint32_t n)
* subtracts op2 from op1
* returns 0 if op1>=op2
* 		   1 if op1<op2
* result is not valid if return value is 1 (or is in 2's compliment :P)
* **************************************************************/
bool subbignum(uint64_t res[], uint64_t op1[], uint64_t op2[], uint32_t n)
{
	bool carry = 0;
	uint32_t i;
	for (i = 0; i<n; i++)
	{
		if (carry)
		{
			if (op1[i] != 0)
				carry = 0;
			op1[i]--;
		}
		if (op1[i]<op2[i])
			carry = 1;

		res[i] = op1[i] - op2[i];
	}
	return carry;
}
bool slnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n)//shift left by n
{
	uint32_t i, x, y;
	uint64_t j, k, carry = 0;
	x = n / 64;
	y = n % 64;

	for (i = len; i - x >0; i--)
	{
		res[i - 1] = op[i - 1 - x];
	}
	for (; i>0; i--)
	{
		res[i - 1] = 0;
	}
	for (i = 0; i<len; i++)
	{
		j = res[i];
		k = 0;
		for (x = 0; x<y; x++)
		{
			if (j & 0x8000000000000000)
			{
				k = (k << 1) | 1;
			}
			else
			{
				k = (k << 1);
			}
			j = j << 1;
		}
		res[i] = j | carry;
		carry = k;
	}
	return 1;
}
bool srnbignum(uint64_t res[], uint64_t op[], uint32_t len, uint32_t n)//shift right by n
{
	uint32_t i, x, y;
	uint64_t j, k, carry = 0;
	x = n / 64;
	y = n % 64;

	for (i = 0; i + x < len; i++)
	{
		res[i] = op[i + x];
	}
	for (; i<len; i++)
	{
		res[i] = 0;
	}
	for (i = len; i>0; i--)
	{
		j = res[i - 1];
		k = 0;
		for (x = 0; x<y; x++)
		{
			if (j & 0x0000000000000001)
			{
				k = (k >> 1) | 0x8000000000000000;
			}
			else
			{
				k = (k >> 1);
			}
			j = j >> 1;
		}
		res[i - 1] = j | carry;
		carry = k;
	}
	return 1;

}
/****************************************************************
* uint32_t bit_length(uint64_t op[],uint32_t n)
* returns position of MSB present
*
*
****************************************************************/
uint32_t bit_length(uint64_t op[], uint32_t n)
{
	uint32_t len = 0;
	uint32_t i;
	uint64_t unit = 1;
	for (; n>0; n--)
	{
		if (op[n - 1] == 0)
			continue;
		for (i = 64; i>0; i--)
		{
			if (op[n - 1] & (unit << (i - 1)))
			{
				len = (64 * (n - 1)) + i;
				break;
			}

		}
		if (len)
			break;
	}
	return len;
}


uint64_t input[18] = { 0 }, out[18] = { 0 },  encrypt[18] = { 0 }, n[18] = { 0 }, d[18] = { 0 }, e[18] = { 0 };

int test_rsa(void) {

	//1024bit
	unsigned char n_data[] = "d5a6d0c5f97a4f5ba303319b990ace065bad0a7b3d4a4fafc84d4642d8a983510ed6c815dbb1bead336d0ff561a160c75a5c2fae65c7908d76466b498f537f6c8279f5769cf6bab9ee9064df56cc6457902ab57f40bb5a45bc4bd389064657754cb3871c6920bfeaf4803a485cde63d131b0f24a836c4ef98c1c9aa4e0ecc261";
	unsigned char d_data[] = "a8475adb0413dd1b9d3aafc1117adc294fddec8a830cdbd4e55c5001e8ab235e1de4f7f59773d96e8c39d3beff25df974549a4d8a51bd974427b5697bac7166dcdb1b474670071482096588c09a6a3e4d109f14be78b0453c77cbe86f72657019f3ba473017289fa9f932043cca6b26e78b051cf833a0b802a9a5c4bed727041";

	e[0] = 0x10001;


	int val = 0;
	int len = strlen(n_data) / 2;
	char *buf = (char*)malloc(len);
	memset(buf, 0, 128);
	for (int i = 0; i < len; i++)
	{
		if (sscanf(n_data+ 2 * (len - 1 - i),"%02x", &val) != 1)
		{
			return 0;
		}
		buf[i] = val;
	}
	memcpy((char*)n, buf, 128);

	memset(buf, 0, 128);
	for (int i = 0; i < len; i++)
	{
		if (sscanf(d_data + 2 * (len - 1 - i), "%02x", &val) != 1)
		{
			return 0;
		}
		buf[i] = val;
	}
	memcpy((char*)d, buf, 128);


	clock_t start_enc, stop_enc, start_dec, stop_dec;
	unsigned long us_enc = 0, us_dec = 0;
#if 0
	char *p = (char*)input;
	for (int i =0; i < 128; i++)
	{
		p[i] = i;
	}
#endif
	strcpy((char*)input, "hello, this is first rsa encode.");


	start_enc = clock();

	rsa1024(encrypt, input, e, n);
	stop_enc = clock();
	//decryption
	start_dec = clock();
	rsa1024(out, encrypt, d, n);
	memset(buf, 0, 128);
	memcpy((char*)buf, (char*)out, 128);

	
	return 0;
}
#else


/*
* This method converts a string bignum to the bignum variable.
* Example usage str2bignum("12345678901234")
* If the base B is 16 then the above number corresponds to the hex
* value of 0xb3a73ce2ff2
*
* */
bignum str2bignum(char * str) {
	int i, j;
	bignum b[11], bignum_primitives[11], output;
	// We will initialise 0...9 as bignums and store it as array of bignums
	i = 0;
	while (i < 10) {
		bignum_primitives[i] = digit2bignum(i);
		i++;
	}
	// initialize bignum 10
	bignum_primitives[10].tab = (integer *)malloc(sizeof(integer) * 4);
	bignum_primitives[10].sign = 1;

	if (B < 10) {
		// We initialise the primitive bignum only when the base is less than 10, else the base
		// primitive number array size would be very large, thus decreasing the code performance.
		i = 0;
		int int_ten = 10;
		bignum_primitives[10].size = 1;
		while (int_ten >= B) {
			bignum_primitives[10].size++;
			bignum_primitives[10].tab[i++] = int_ten % B;
			int_ten /= B;
		}
		bignum_primitives[10].tab[i] = int_ten;
	}
	else {
		bignum_primitives[10].tab[0] = 10;
		bignum_primitives[10].size = 1;
	}

	j = 0;
	output.sign = 1;
	output.size = 1;
	output.tab = (integer *)malloc(sizeof(integer));
	output.tab[0] = 0;
	if (str[0] == '-') {
		j = 1;
	}
	integer *temp;
	temp = output.tab;
	output = add(output, bignum_primitives[str[j++] - '0']);
	free(temp);
	for (i = j; i < strlen(str); i++) {
		int digit = str[i] - '0';
		if (digit < 0 || digit > 9) {
			perror(NUMBER_FORMAT_ERROR);
			exit(0);
		}

		temp = output.tab;
		output = mult(output, bignum_primitives[10]);
		free(temp);

		temp = output.tab;
		output = add(output, bignum_primitives[str[i] - '0']);
		free(temp);
	}
	// If the sign of the string number is -ve, we set the sign int as -1
	if (str[0] == '-')
		output.sign = -1;

	for (i = 0; i <= 10; i++) {
		free(bignum_primitives[i].tab);
		bignum_primitives[i].tab = NULL;
	}
	return output;
}

/*
* Returns the sum of the two input bignums.
* */
bignum add(bignum a, bignum b) {
	if (a.sign == 1 && b.sign == -1) {
		// else if b input is negative we return a-b
		b.sign = 1;
		return sub(a, b);
	}
	else if (a.sign == -1 && b.sign == 1) {
		// if a is negative we return b-a
		a.sign = 1;
		return sub(b, a);
	}
	else if (b.size > a.size) {
		return add(b, a);
	}

	bignum sum;
	sum.sign = a.sign;
	sum.size = a.size;
	sum.tab = (integer *)malloc((a.size + 1) * sizeof(integer));

	//
	int i;
	integer  tmp;
	integer carry = 0;
	for (i = 0; i < b.size; i++) {
		tmp = a.tab[i] + b.tab[i] + carry;
		sum.tab[i] = tmp % B;
		carry = tmp / B;
	}
	for (; i < a.size; i++) {
		tmp = a.tab[i] + carry;
		carry = tmp / B;
		sum.tab[i] = tmp % B;
	}

	sum.tab[i] = carry;
	if (carry)
		sum.size++;

	return sum;
}

/*
* Returns (a-b)
* */
bignum sub(bignum a, bignum b) {
	bignum difference;

	if (a.sign == 1 && b.sign == -1) {// Since a-(-b) = a+b
		b.sign = 1;
		return add(a, b);
	}
	else if (a.sign == -1 && b.sign == 1) {// Since -a-b= -(a+b)
		b.sign = -1;
		return add(a, b);
	}
	else if (a.sign == -1 && b.sign == -1) {// Since -a-(-b)= b-a
		a.sign = 1;
		b.sign = 1;
		return sub(b, a);
	}
	if (b.size > a.size) {// if b>a then a-b= -(b-a)
		difference = sub(b, a);
		difference.sign = -1;
		return difference;
	}
	int i;
	integer carry, temp;
	if (a.size == b.size) {
		for (i = a.size - 1; (i >= 0) && (a.tab[i] == b.tab[i]); i--);// i will be -1, if both a and b are exactly same bignum
		if (i == -1) {
			difference.sign = 1;
			difference.size = 1;
			difference.tab = (integer *)malloc(sizeof(integer));
			difference.tab[0] = 0;
			return difference;
		}

		difference.size = i + 1;
		difference.tab = (integer *)malloc(difference.size * sizeof(integer));
		carry = 0;
		int j;
		if (a.tab[i] > b.tab[i]) {// If a particular element of an array of the bignum "a" is larger than the bignum "b", we perform subtraction till this larger number in the array and put the difference sign as +ve else -ve
			difference.sign = 1;
			for (j = 0; j <= i; j++) {
				temp = a.tab[j] - b.tab[j] + carry;
				carry = (temp < 0) ? -1 : 0;
				difference.tab[j] = (temp + B) % B;
			}
		}
		else {// It will enter here only if a>b, other cases are covered before. If so, we set the sign of the difference as the sign of a and follow the classic algorithm
			difference.sign = -1;
			for (j = 0; j <= i; j++) {
				temp = b.tab[j] - a.tab[j] + carry;
				carry = (temp < 0) ? -1 : 0;
				difference.tab[j] = (temp + B) % B;
			}
		}
	}
	else {
		difference.sign = a.sign;
		difference.size = a.size;
		difference.tab = (integer *)malloc((difference.size) * sizeof(integer));
		carry = 0;
		for (i = 0; i < b.size; i++) {
			temp = a.tab[i] - b.tab[i] + carry;
			carry = (temp < 0) ? -1 : 0;
			difference.tab[i] = (temp + B) % B;
		}

		for (; i < a.size; i++) {
			temp = a.tab[i] + carry;
			carry = (temp < 0) ? -1 : 0;
			difference.tab[i] = (temp + B) % B;
		}
	}
	for (i = difference.size - 1; difference.tab[i] == 0; i--);
	difference.size = i + 1;// We update the size of the difference with the size of difference.tab array
	return difference;
}
/*
* Returns the product of inputs a and b
* */
bignum mult(bignum a, bignum b) {
	bignum product;

	if (iszero(a) || iszero(b)) {// product is zero if any of its input is zero
		product.tab = (integer *)malloc(product.size * sizeof(integer));
		product.tab[0] = 0;
		product.sign = 1;
		product.size = 1;
		return product;
	}

	if (b.size > a.size) //If b>a, we swap the values of a and b
		return mult(b, a);

	product.sign = a.sign * b.sign;
	product.size = a.size + b.size;
	product.tab = (integer *)malloc((product.size) * sizeof(integer));
	int i;
	for (i = 0; i < product.size; i++)
		product.tab[i] = 0;
	integer carry;
	for (i = 0; i < b.size; i++) {//Classical bignum multiplication algorithm
		carry = 0;
		int j;
		integer tmp;
		for (j = 0; j < a.size; j++) {
			tmp = b.tab[i] * a.tab[j] + product.tab[i + j] + carry;
			carry = tmp / B;
			product.tab[i + j] = tmp % B;
		}
		product.tab[i + a.size] = carry;
	}

	for (i = product.size - 1; product.tab[i] == 0; i--);
	product.size = i + 1;
	return product;
}

/*
*  This method divides a by n and returns the remainder.
*	We have not implemented the algorithm given in slide, rather we followed the algorithm given in reference.(With an exponent)
*	We have implemented so because, it computes remainder in linear time scale.
* */
bignum reminder(bignum a, bignum n) {
	int isEqual;
	bignum remainder;
	isEqual = compare(a, n);
	if (isEqual == 0) {// return 0 if both a and n are same
		remainder.tab = (integer *)malloc(sizeof(integer));
		remainder.tab[0] = 0;
		remainder.size = 1;
		remainder.sign = 1;
		return remainder;
	}
	else if (isEqual == -1) {// isEqual is -1 when a<n, so we return a as reminder in this case
		copy(&remainder, a);
		return remainder;
	}

	bignum *temp_quorem;
	if (isnormalized(n)) {// If n is normalised then we perform normalised division and return the intermediate quorem as remainder
		temp_quorem = normalized_divi(a, n);
		remainder = temp_quorem[1];
		free(temp_quorem[0].tab);
		free(temp_quorem);
		return remainder;
	}
	int i;
	for (i = E - 1; i >= 0; i--)// E is the log2(Base), for hexadecimal value, E is 4.
		if ((n.tab[n.size - 1] >> i) & 0x1)
			break;
	bignum lshifted_a, lshifted_n, lshifted_r;
	lshifted_a = leftshift(a, E - i - 1);
	lshifted_n = leftshift(n, E - i - 1);
	temp_quorem = normalized_divi(lshifted_a, lshifted_n);
	lshifted_r = temp_quorem[1];
	remainder = rightshift(lshifted_r, E - i - 1);

	free(lshifted_a.tab);
	free(lshifted_n.tab);
	free(lshifted_r.tab);
	free(temp_quorem[0].tab);
	free(temp_quorem);

	return remainder;
}

/*
* Returns (a + b) mod n
* */
bignum addmod(bignum a, bignum b, bignum n) {
	bignum sum = add(a, b);
	bignum output = reminder(sum, n);// we find remainder using the linear time algorithm
	sum.tab = NULL;
	free(sum.tab);
	return output;
}

/*
* Returns ( a * b ) mod n
* */
bignum multmod(bignum a, bignum b, bignum n) {
	bignum prd = mult(a, b);
	bignum res = reminder(prd, n);
	prd.tab = NULL;
	free(prd.tab);
	return res;
}

/*
* Returns (a^b) mod n
* */
bignum expmod(bignum a, bignum b, bignum n) {
	integer *t;
	int start;
	start = length(b) % E;
	if (start == 0) // if length of b is divisible by E, we take start as E.
		start = E;
	int j;
	bignum result = reminder(a, n); // We first start with a mod n
	for (j = start - 2; j >= 0; j--) {
		t = result.tab;
		result = multmod(result, result, n); // Then we square the mod result
		free(t);
		if (((b.tab[b.size - 1] >> j) & 0x1) == 1) { // We right shift the last part of b j times and check if the right-most-bit. if so result is result*a mod n
			t = result.tab;
			result = multmod(result, a, n);
			free(t);
		}
	}
	int i;
	for (i = b.size - 2; i >= 0; i--) {
		for (j = E - 1; j >= 0; j--) {
			t = result.tab;
			result = multmod(result, result, n);
			free(t);
			if (((b.tab[i] >> j) & 0x1) == 1) {
				t = result.tab;
				result = multmod(result, a, n);
				free(t);
			}
		}
	}
	return result;
}

/*
* Returns 0 if a is composite and returns 1 if a is prime
* This performs fermats test to check the primality of "a"
* */
int fermat(bignum a, int t) {
	int i;
	for (i = 0; i<t; i++) {
		bignum n;
		while (1) {
			n = genrandom(length(a) - 1);// Random number between 2 to a-2
			if ((compare(n, sub(a, digit2bignum(2))) == -1) && (compare(n, digit2bignum(2)) == 1)) { //check if 2 < n < (a-2)
				break;
			}
		}
		bignum r = expmod(n, sub(a, digit2bignum(1)), a);
		if (compare(r, digit2bignum(1)) != 0) { // if r = 1, then n is composite
			return 0;
		}
	}
	return 1; // if r!=1 for t runs, then n is prime
}

/*
* Returns a positive random number of given length
* */
bignum genrandom(int length) {
	bignum output;
	if (length == 0) {// if length is 0, we always return 0
		output.sign = 1;
		output.size = 1;
		output.tab = (integer *)malloc(sizeof(integer));
		output.tab[0] = 0;
		return output;
	}
	output.size = length / E;
	output.sign = 1;// we always return +ve random number
	if (length % E != 0)
		output.size++; // we fix the size of tab to be |length/E| + length%E
	output.tab = (integer *)malloc(sizeof(integer)*output.size);
	int i;
	for (i = 0; (i + 1) * E < length; i++) {
		output.tab[i] = rand() % B; //we fill the tab array with random integers of given base
	}
	int n;
	n = length - i*E;
	output.tab[i] = ((integer)rand()) % B;
	output.tab[i] |= ((integer)0x1 << (n - 1));
	int j;
	for (j = n; j < E; j++)
		output.tab[i] &= ~((integer)0x1 << j);

	return output;
}
/*
* Returns a positive random prime number
* Uses fermats test to check for primality
* */
bignum genrandomprime(int length) {
	bignum p = genrandom(length);
	while (!fermat(p, TEST_CNT)) { //1 -
		free(p.tab);
		p.tab = NULL;
		p = genrandom(length);
	}

	return p;
}
/*
* This method prints the value of the input bignum
* For E.g. The
* */
void printbignum(bignum num) {
	int i;
	if (B != 16) {
		i = num.size - 1;
		while (i >= 0) {
			printf("[%3d] - %lu\n", i, num.tab[i]);
			i--;
		}
		printf("Base = %ld, %s\n", B, num.sign == 1 ? "+ve" : "-ve");
	}
	else {
		// Hexadecimal value, since base is 16
		if (num.sign == -1) printf("-");
		printf("0x");
		i = num.size - 1;
		while (i >= 0) {
			printf("%x", num.tab[i]);
			i--;
		}
		printf("\n");
	}
}

/*
* This is a utility method to convert a single digit int to a bignum variable
*/
bignum digit2bignum(int digit) {
	if (digit < 0 || digit > 9) {
		perror(NUMBER_FORMAT_ERROR_1);
		exit(1);
	}

	bignum output;
	int i = 0;

	output.sign = 1;
	output.tab = (integer *)malloc(sizeof(integer) * 4);
	output.size = 1;
	while (digit >= B) {
		output.tab[i++] = digit % B;
		digit /= B;
		output.size++;
	}
	output.tab[i] = digit;

	return output;
}

// ************************************************************* Other Utility functions *******************************************************

/*
* Copies bignum from source to destination
* */
void copy(bignum *destination, bignum source) {
	if (destination == &source) // If address of both are same, do nothing
		return;
	*destination = source;
	destination->tab = (integer *)malloc(destination->size * sizeof(integer));
	memcpy(destination->tab, source.tab, destination->size * sizeof(integer));
}

/*
* Returns 1 if a is 0 and returns 0 if a!=0
* */
int iszero(bignum a) {
	return (a.size == 1) && (a.tab[0] == 0);
}

/*
* Returns 1 if a is 1 and returns 0 if a!=1
* */
int isone(bignum a) {
	return (a.size == 1) && (a.sign == 1) && (a.tab[0] == 1);
}

/*
* This method is used to compare two bignum a and b
* Returns  1: if a > b
* Returns  0: if a = b
* Returns -1: if a < b
*/
int compare(bignum a, bignum b) {
	if (a.sign == -1 && b.sign == 1) // If a is -ve and b is +ve, then return -1 (implies a is smaller than b)
		return -1;
	if (a.sign == 1 && b.sign == -1) // If a is +ve and b is -ve, then return 1 (implies b is smaller than a)
		return 1;

	if (a.sign == -1 && b.sign == -1) {// If both a and b are -ve, then inverse the sign of both and call same method with this inverted value
		a.sign = b.sign = 1;
		return compare(b, a);
	}

	if (a.size < b.size)
		return -1;
	if (a.size > b.size)
		return 1;

	int i; // it reaches here only if size of a and b are same
	for (i = a.size - 1; i >= 0; i--) // If so, we compare from the most significant digit
		if (a.tab[i] < b.tab[i])
			return -1;
		else if (a.tab[i] > b.tab[i])
			return 1;

	return 0;
}


/*
* Leftshifts a by k index and returns the output
* */
bignum leftshift(bignum a, int k) {
	int i, len = length(a) + k;

	bignum res;
	res.sign = 1;
	res.size = (len / E) + ((len%E == 0) ? 0 : 1);
	res.tab = (integer *)malloc((res.size) * sizeof(integer));

	int m = k / E, n = k%E;
	for (i = 0; i < m; i++)
		res.tab[i] = 0;
	if (n == 0)
		for (i = m; i < res.size; i++)
			res.tab[i] = a.tab[i - m];
	else {
		res.tab[m] = (((a.tab[0] << n) & (integer)MASK));
		for (i = m + 1; i < res.size - 1; i++) {
			res.tab[i] = a.tab[i - m - 1] >> (E - n);
			res.tab[i] |= (((a.tab[i - m] << n) & (integer)MASK));
		}
		res.tab[i] = a.tab[i - m - 1] >> (E - n);
		if (i - m < a.size)
			res.tab[i] |= (((a.tab[i - m] << n) & (integer)MASK));
	}

	return res;
}
/*
* Rightshifts a by k index and returns the output
* */
bignum rightshift(bignum a, int k) {
	int i, len = length(a) - k;

	bignum res;
	res.sign = 1;

	if (len <= 0) {
		res.size = 1;
		res.tab = (integer *)malloc(sizeof(integer));
		res.tab[0] = 0;

		return res;
	}

	res.size = (len / E) + ((len%E == 0) ? 0 : 1);
	res.tab = (integer *)malloc((res.size) * sizeof(integer));

	int m = k / E, n = k%E;
	if (n == 0) {
		for (i = 0; i < res.size; i++)
			res.tab[i] = a.tab[i + m];
	}
	else {
		for (i = 0; i < res.size - 1; i++) {
			res.tab[i] = a.tab[i + m] >> n;
			res.tab[i] |= ((a.tab[i + m + 1] << (E - n)) & MASK);
		}
		res.tab[i] = a.tab[i + m] >> n;
		if (i + m + 1 < a.size)
			res.tab[i] |= ((a.tab[i + m + 1] << (E - n)) & MASK);
	}

	return res;
}



/*
* Performs bignum division and returns a/n
* */
bignum divi(bignum a, bignum n) {
	int comp;
	bignum output;

	comp = compare(a, n);
	if (comp == -1) { // if a<n, return 0
		output.sign = output.size = 1;
		output.tab = (integer *)malloc(sizeof(integer));
		output.tab[0] = 0;
		return output;
	}
	if (comp == 0) {// if a==n, return 1
		output.sign = output.size = 1;
		output.tab = (integer *)malloc(sizeof(integer));
		output.tab[0] = 1;
		return output;
	}
	bignum  *temp_quorem;;

	if (isnormalized(n)) {// if n is normalised, then we perform normalised division (a/n) and return quorem
		temp_quorem = normalized_divi(a, n);
		output = temp_quorem[0];
		free(temp_quorem[1].tab);
		free(temp_quorem);

		return output;
	}
	int i;
	for (i = E - 1; i >= 0; i--)
		if ((n.tab[n.size - 1] >> i) & 0x1)
			break;
	bignum leftshifted_a, leftshifted_n;
	leftshifted_a = leftshift(a, E - i - 1);
	leftshifted_n = leftshift(n, E - i - 1);
	temp_quorem = normalized_divi(leftshifted_a, leftshifted_n);
	output = temp_quorem[0];

	free(temp_quorem[1].tab);
	free(temp_quorem);
	free(leftshifted_a.tab);
	free(leftshifted_n.tab);
	return output;
}

/*
* Returns the length of bignum a
* */
int length(bignum a) {
	int length = a.size * E;
	integer n = a.tab[a.size - 1];
	int i;
	for (i = E - 1; i > 0; i--)
		if (((n >> i) & 0x1) == 0)
			length--;
		else
			break;
	return length;
}
/*
* Returns inverse of a mod n
* */
bignum inverse(bignum a, bignum n) {
	bignum r[2], v[2], q;

	r[0] = reminder(n, a);
	copy(&r[1], a);
	q = divi(n, a);

	v[1] = digit2bignum(1);

	copy(&v[0], q);
	free(q.tab);
	if (!iszero(v[0]))
		v[0].sign *= -1;

	integer *t;

	bignum tmp0, tmp1;
	int mark = 0, mark1 = 1;
	while (!iszero(r[mark])) {
		mark ^= 1;
		mark1 ^= 1;

		q = divi(r[mark], r[mark1]);

		t = r[mark].tab;
		r[mark] = reminder(r[mark], r[mark1]);
		free(t);

		tmp0 = mult(q, v[mark1]);
		tmp1 = sub(v[mark], tmp0);

		free(v[mark].tab);
		v[mark] = reminder(tmp1, n);

		free(q.tab);
		free(tmp0.tab);
		free(tmp1.tab);
	}

	tmp0 = add(v[mark ^ 1], n);
	bignum output = reminder(tmp0, n);

	free(tmp0.tab);
	free(v[0].tab);
	free(v[1].tab);
	free(r[0].tab);
	free(r[1].tab);

	return output;
}

/*
* Returns GCD of two bignums a and b
* */
bignum gcd(bignum a, bignum b) {
	bignum output;
	output.sign = 1;

	if (iszero(b)) { // if b==0, then gcd(a,b)=a
		output.tab = (integer *)malloc((output.size) * sizeof(integer));
		copy(&output, a);
		return output;
	}
	if (iszero(a)) {// if a==0, then gcd(a,b)=b
		output.tab = (integer *)malloc((output.size) * sizeof(integer));
		copy(&output, b);
		return output;
	}
	bignum tmp;

	if (compare(a, b)) {//if a!=b, we
		tmp = reminder(a, b);
		output = gcd(b, tmp);
		free(tmp.tab);
		return output;
	}
	else {
		tmp = reminder(b, a);
		output = gcd(a, tmp);
		free(tmp.tab);
		return output;
	}
}

/*
* A bignum is normalised when its MSB is 1
*/
int isnormalized(bignum a) {
	if (a.sign == -1)
		return 0;
	return  0x1 & (a.tab[a.size - 1] >> (E - 1));
}

// We can perform normalised division only if a > b > 0, and b is normalized;
/*
* Returns an array, with quotient as first element and remainder as second element
* */
bignum * normalized_divi(bignum a, bignum b) {
	bignum r, remainder;

	remainder.sign = 1;
	remainder.size = a.size;
	remainder.tab = (integer *)malloc(sizeof(integer)*(remainder.size + 1));

	int i, k = a.size;
	for (i = 0; i < k; i++)
		remainder.tab[i] = a.tab[i];
	remainder.tab[k] = 0;
	int l = b.size;
	bignum quotient;
	quotient.sign = 1;
	quotient.size = k - l + 1;
	quotient.tab = (integer *)malloc(sizeof(integer)*quotient.size);
	integer temp;
	for (i = k - l; i >= 0; i--) {
		quotient.tab[i] = (remainder.tab[i + l] * B + remainder.tab[i + l - 1]) / b.tab[l - 1];
		if (quotient.tab[i] >= B)
			quotient.tab[i] = B - 1;

		int carry = 0;
		int j;
		for (j = 0; j < l; j++) {
			temp = remainder.tab[i + j] - quotient.tab[i] * b.tab[j] + carry;
			carry = temp / B;
			remainder.tab[i + j] = temp % B;
			if (temp < 0 && remainder.tab[i + j] != 0) {
				carry -= 1;
				remainder.tab[i + j] = remainder.tab[i + j] + B;
			}
		}
		remainder.tab[i + l] += carry;

		while (remainder.tab[i + l] < 0) {
			carry = 0;
			for (j = 0; j < l; j++) {
				temp = remainder.tab[i + j] + b.tab[j] + carry;
				carry = temp / B;
				remainder.tab[i + j] = temp % B;
			}
			remainder.tab[i + l] += carry;
			quotient.tab[i]--;
		}
	}

	for (i = k - l; i >= 1 && quotient.tab[i] == 0; i--);
	quotient.size = i + 1;
	for (i = l - 1; i >= 1 && remainder.tab[i] == 0; i--);
	remainder.size = i + 1;

	bignum * output = (bignum *)malloc(sizeof(bignum) * 2);
	output[0] = quotient;
	output[1] = remainder;
	return output;
}

/*
* Returns the keys generated for RSA encryption
* */
void keygen(bignum * n, bignum * e, bignum * d, int len) {
	bignum p, q, phi_n;
	bignum t0, t1, bgcd, tmp;
	bignum ONE = digit2bignum(1);

	p = genrandomprime(len);
	q = genrandomprime(len);

	while (compare(p, q) == 0) {
		free(q.tab);
		q = genrandomprime(len);
	}
	*n = mult(p, q);
	t0 = sub(p, ONE);
	t1 = sub(q, ONE);
	phi_n = mult(t0, t1);
	free(t0.tab);
	free(t1.tab);

	*e = digit2bignum(3);

	while (1) {
		bgcd = gcd(*e, phi_n);
		if (compare(bgcd, ONE) == 0) {
			free(bgcd.tab);

			*d = inverse(*e, phi_n);
			break;
		}

		int e_len;
		do {
			e_len = rand() % (length(*n));
		} while (e_len <= 1);

		do {
			free(e->tab);
			*e = genrandom(e_len);
		} while (iszero(*e) || isone(*e));
	}

	free(ONE.tab);
	free(p.tab);
	free(q.tab);
	free(phi_n.tab);
}

/*
* Encrypts the input message m with public key e and public modulus n
* */
bignum RSAencrypt(bignum m, bignum e, bignum n) {
	return expmod(m, e, n);
}

/*
* Decrypts the cipher c with private key d and public modulus n
* */
bignum RSAdecrypt(bignum c, bignum d, bignum n) {
	return expmod(c, d, n);
}

#endif
