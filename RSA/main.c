#include <stdio.h>
#include <stdlib.h>
#include "xxhash.h"

// square and multiply
long long squareAndMultiply(int a, int p, int n);
// prime -> 1, composite -> -1
int milerRabinTest(int n);
// mod inverse using with extended euclid
int modInverse(int a, int n);
// encryption RSA
long long encrypt_RSA(int m, int e, int n);

int main() {
	int n, phi;
	int i, j;
	int p, q, r, e, d;
	long long message_in, message_out;
	long long cipher;
	char buf[65];

	//****************************************
	//key setup
	//****************************************	
	p = rand() % 1024;
	while (milerRabinTest(p) < 0) {
		p = rand() % 1024;
	}
	q = rand() % 1024;
	while (milerRabinTest(q) < 0) {
		q = rand() % 1024;
	}
	r = rand() % 1024;
	while (milerRabinTest(r) < 0) {
		r = rand() % 1024;
	}
	n = p*q*r;
	phi = (p - 1)*(q - 1)*(r - 1);

	e = rand() % phi;
	while (milerRabinTest(e) < 0) {
		e = rand() % phi;
	}
	d = modInverse(e, phi);

	printf("p = %d\n", p);
	printf("q = %d\n", q);
	printf("r = %d\n", r);
	printf("N = %d\n", n);
	printf("phi = %d\n", phi);
	printf("e = %d\n", e);
	printf("d = %d\n\n", d);

	printf("Message Input : ");
	scanf("%lld", &message_in);
	printf("Message : %lld\n\n", message_in);

	// Digital Signature
	sprintf(buf, "%l64u", message_in);
	unsigned __int64 hash = XXH64(buf, sizeof(buf) - 1, 0);

	printf("**Encryption\n");
	cipher = encrypt_RSA(message_in, e, n);
	printf("cipher : %lld\n\n", cipher);

	message_out = encrypt_RSA(cipher, d, n);
	printf("**Decryption\n");
	printf("decrypted cipher : %lld\n\n", message_out);

	return 0;
}

long long squareAndMultiply(int a, int p, int n) {
	int binary[32] = { 0 };
	int idx = 0;
	int i;
	long long val = 1;
	while (p > 0) {
		binary[idx++] = p % 2;
		p /= 2;
	}
	for (i = idx - 1; i >= 0; i--) {
		val = ((val % n) * (val % n)) % n;
		if (binary[i] == 1) {
			val = ((val % n) * (a % n)) % n;
		}		
	}	
	return val;
}

int milerRabinTest(int n) {
	int cmp = n - 1;
	int m, k, t;
	int count = 0;
	int i;	
	int a;

	while (cmp % 2 == 0) {
		cmp /= 2;
		count++;
	}
	m = cmp;
	k = count;
	for (i = 0; i < 20; i++) {
		a = rand() % (n - 1);
		t = squareAndMultiply(a, (1 << i) * m, n);
		if (t % n == n - 1)
			return 1;
	}
	return -1;
}

int modInverse(int a, int n) {
	int a1 = 1, a2 = 0, a3 = n;
	int b1 = 0, b2 = 1, b3 = a;
	int t1, t2, t3;
	int q;
	int rtn;

	while (1) {
		// no inverse
		if (b3 == 0) {
			rtn = -1;
			break;
		}
		// mod inverse
		if (b3 == 1) {
			rtn = (b2 < 0) ? b2 + n : b2;
			break;
		}
		q = a3 / b3;
		t1 = a1 - q * b1;
		t2 = a2 - q * b2;
		t3 = a3 - q * b3;
		a1 = b1;
		a2 = b2;
		a3 = b3;
		b1 = t1;
		b2 = t2;
		b3 = t3;
	}
	return rtn;
}

long long encrypt_RSA(int m, int e, int n) {
	return squareAndMultiply(m, e, n);
}

