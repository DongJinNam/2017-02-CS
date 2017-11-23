#include <stdio.h>
#include <stdlib.h>
#include "xxhash.h"

typedef long long ll;

// square and multiply
ll squareAndMultiply(ll a, ll p, ll n);
// prime -> 1, composite -> -1
ll milerRabinTest(ll n);
// mod inverse using with extended euclid
ll modInverse(ll a, ll n);
// encryption RSA
ll encrypt_RSA(ll m, ll e, ll n);

int main() {
	ll n, phi;
	int i, j;
	ll p, q, r, e, d;
	ll hashed, hashed2, hashed3, sign;
	ll message_in, message_out;
	ll cipher;	
	unsigned __int64 hash, hash2;
	char buf[65], buf2[65];

	srand(time(NULL));

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

	printf("p = %lld\n", p);
	printf("q = %lld\n", q);
	printf("r = %lld\n", r);
	printf("N = %lld\n", n);
	printf("phi = %lld\n", phi);
	printf("e = %lld\n", e);
	printf("d = %lld\n\n", d);

	printf("Message Input : ");
	scanf("%lld", &message_in);
	printf("Message : %lld\n\n", message_in);

	// Digital Signature Sign
	sprintf(buf, "%lld", message_in);
	hash = XXH64(buf, sizeof(buf) - 1, 0);
	hashed = hash % n;

	printf("**Encryption\n");
	cipher = encrypt_RSA(message_in, e, n);
	sign = squareAndMultiply(hashed, d, n);
	printf("cipher : %lld\n\n", cipher);

	printf("**Generate signature\n");
	printf("message's hash value : %d\n",hashed);
	printf("generated signature : %d\n", sign);
	printf("\n\n");

	message_out = encrypt_RSA(cipher, d, n);
	printf("**Decryption\n");
	printf("decrypted cipher : %lld\n\n", message_out);

	// Digital Signature Verify
	sprintf(buf2, "%lld", message_out);
	hash2 = XXH64(buf2, sizeof(buf2) - 1, 0);
	hashed2 = hash2 % n;
	hashed3 = squareAndMultiply(sign, e, n);

	printf("**Verify signature\n");
	printf("received signature value : %d\n",sign);
	printf("decrypted message's hash value : %d\n", hashed2);
	printf("verify value from signature : %d\n", hashed3);

	if (hashed2 == hashed3)
		printf("Signature valid!\n");
	else
		printf("Signature not valid!\n");
	return 0;
}

ll squareAndMultiply(ll a, ll p, ll n) {
	int binary[64] = { 0 };
	int idx = 0;
	int i;
	ll val = 1;
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

ll milerRabinTest(ll n) {
	ll cmp = n - 1;
	ll m, k, t;
	ll count = 0;
	ll a;
	int i;	
	
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

ll modInverse(ll a, ll n) {
	ll a1 = 1, a2 = 0, a3 = n;
	ll b1 = 0, b2 = 1, b3 = a;
	ll t1, t2, t3;
	ll q;
	ll rtn;
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

ll encrypt_RSA(ll m, ll e, ll n) {
	return squareAndMultiply(m, e, n);
}

