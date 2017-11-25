#include <stdio.h>
#include <stdlib.h>
#include "xxhash.h"

typedef long long ll; // long long -> ll

// square and multiply algorithm
ll squareAndMultiply(ll a, ll p, ll n);
// 매개변수 n이 소수인지 아닌지 판별하는 함수.
ll isPrime(ll n);
// 소수인지 아닌지 판별하기 위해 miller-rabin primarlity test를 사용합니다.
ll millerRabinTest(ll d, ll n);
// mod inverse using with extended euclidean algorithm
ll modInverse(ll a, ll n);

int main() {
	ll n, phi; // (p*q*r), ((p-1)*(q-1)*(r-1))
	int i, j; // for or while loop iterator
	ll p, q, r, e, d; // 30-bit triple RSA(p,q,r) + 암호화 결과, 복호화 결과 (e,d)
	ll hashed, hashed2, hashed3, sign;
	ll message_in, message_out; // 암호화 전 정수, 복호화 후 정수
	ll cipher; // 암호화된 정수	
	unsigned __int64 hash, hash2;
	char buf[65], buf2[65]; // 전자서명에서 사용할 버퍼.

	//****************************************
	//key setup with miler-rabin test
	//****************************************	
	srand(time(NULL)); // random
	p = rand() % 1024;
	while (isPrime(p) < 0) {
		p = rand() % 1024;
	}
	q = rand() % 1024;
	while (isPrime(q) < 0) {
		q = rand() % 1024;
	}
	r = rand() % 1024;
	while (isPrime(r) < 0) {
		r = rand() % 1024;
	}
	n = p*q*r;
	phi = (p - 1)*(q - 1)*(r - 1);
	// e - random prime
	e = rand() % phi;
	while (isPrime(e) < 0) {
		e = rand() % phi;
	}
	// d - multiplicative inverse (extended euclidean algorithm 사용)
	d = modInverse(e, phi);

	printf("p = %lld\n", p);
	printf("q = %lld\n", q);
	printf("r = %lld\n", r);
	printf("N = %lld\n", n);
	printf("phi = %lld\n", phi);
	printf("e = %lld\n", e);
	printf("d = %lld\n\n", d);

	printf("Message Input : ");
	scanf("%lld", &message_in); // 입력받은 정수 출력
	printf("Message : %lld\n\n", message_in);

	// Digital Signature Sign
	sprintf(buf, "%lld", message_in);
	hash = XXH64(buf, sizeof(buf) - 1, 0);
	hashed = hash % n;

	// 전자서명 혹은 RSA 암호화/복호화 과정에서 square and multiply algorithm을 사용합니다.
	printf("**Encryption\n");
	cipher = squareAndMultiply(message_in, e, n);
	sign = squareAndMultiply(hashed, d, n); // 전자서명 값.
	printf("cipher : %lld\n\n", cipher); // 암호화된 정수 출력

	printf("**Generate signature\n");
	printf("message's hash value : %lld\n",hashed); // 입력받은 정수 hash 함수 결과물
	printf("generated signature : %lld\n", sign); // 전자서명 결과값
	printf("\n\n");

	message_out = squareAndMultiply(cipher, d, n); // 복호화 과정도 square and multiply algorithm을 사용한다.
	// message_out += 1; (중간에서 메시지를 조작하기 위한 코드이기 때문에 주석처리를 하였습니다.)
	printf("**Decryption\n");
	printf("decrypted cipher : %lld\n\n", message_out);

	// Digital Signature Verify
	sprintf(buf2, "%lld", message_out); // 복호화 과정을 거친 정수 출력
	hash2 = XXH64(buf2, sizeof(buf2) - 1, 0); // 복호화 결과 정수로 hash 함수 적용
	hashed2 = hash2 % n; // compare value with hashed3
	hashed3 = squareAndMultiply(sign, e, n); // compare value with hashed2

	printf("**Verify signature\n");
	printf("received signature value : %lld\n",sign);
	printf("decrypted message's hash value : %lld\n", hashed2);
	printf("verify value from signature : %lld\n", hashed3);

	// hashed2 와 hashed3 이 같아야 전자서명이 valid하다.
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
	ll val = 1; // 초기값은 1로 설정
	while (p > 0) { // p값을 이진수로 변환
		binary[idx++] = p % 2;
		p /= 2;
	}
	for (i = idx - 1; i >= 0; i--) {
		val = ((val % n) * (val % n)) % n; // bit 값이 1,0 모두 square 연산을 진행한다.
		if (binary[i] == 1) { 
			val = ((val % n) * (a % n)) % n; // bit 값이 1인 경우, 기존 결과에 a를 한번 곱한다.
		}		
	}	
	return val;
}

// 매개변수 값이 소수인지 아닌지 판별하는 함수.
ll isPrime(ll n)
{
	if (n <= 1 || n == 4) return -1;
	if (n <= 3) return 1;

	ll d = n - 1;
	while (d % 2 == 0)
		d /= 2;

	for (int i = 0; i < 20; i++)
		if (millerRabinTest(d, n) == -1)
			return -1; // -1 : 합성수
	return 1; // 1 : 소수
}

ll millerRabinTest(ll d, ll n) {
	// 2 ~ n-2 범위에 있는 임의의 숫자 선택
	ll a = 2 + rand() % (n - 4);

	// a^d % n
	ll x = squareAndMultiply(a, d, n);

	if (x == 1 || x == n - 1)
		return 1; // 소수

	while (d != n - 1)
	{
		x = (x * x) % n;
		d *= 2;
		if (x == 1) return -1; // -1 : 합성수
		if (x == n - 1) return 1; // 1 : 소수
	}
	// -1 : 합성수
	return -1;
}

ll modInverse(ll a, ll n) {
	// Extended Euclidean Algorithm을 사용하였습니다.
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
