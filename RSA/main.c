#include <stdio.h>
#include <stdlib.h>
#include "xxhash.h"

typedef long long ll; // long long -> ll

// square and multiply algorithm
ll squareAndMultiply(ll a, ll p, ll n);
// �Ű����� n�� �Ҽ����� �ƴ��� �Ǻ��ϴ� �Լ�.
ll isPrime(ll n);
// �Ҽ����� �ƴ��� �Ǻ��ϱ� ���� miller-rabin primarlity test�� ����մϴ�.
ll millerRabinTest(ll d, ll n);
// mod inverse using with extended euclidean algorithm
ll modInverse(ll a, ll n);

int main() {
	ll n, phi; // (p*q*r), ((p-1)*(q-1)*(r-1))
	int i, j; // for or while loop iterator
	ll p, q, r, e, d; // 30-bit triple RSA(p,q,r) + ��ȣȭ ���, ��ȣȭ ��� (e,d)
	ll hashed, hashed2, hashed3, sign;
	ll message_in, message_out; // ��ȣȭ �� ����, ��ȣȭ �� ����
	ll cipher; // ��ȣȭ�� ����	
	unsigned __int64 hash, hash2;
	char buf[65], buf2[65]; // ���ڼ����� ����� ����.

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
	// d - multiplicative inverse (extended euclidean algorithm ���)
	d = modInverse(e, phi);

	printf("p = %lld\n", p);
	printf("q = %lld\n", q);
	printf("r = %lld\n", r);
	printf("N = %lld\n", n);
	printf("phi = %lld\n", phi);
	printf("e = %lld\n", e);
	printf("d = %lld\n\n", d);

	printf("Message Input : ");
	scanf("%lld", &message_in); // �Է¹��� ���� ���
	printf("Message : %lld\n\n", message_in);

	// Digital Signature Sign
	sprintf(buf, "%lld", message_in);
	hash = XXH64(buf, sizeof(buf) - 1, 0);
	hashed = hash % n;

	// ���ڼ��� Ȥ�� RSA ��ȣȭ/��ȣȭ �������� square and multiply algorithm�� ����մϴ�.
	printf("**Encryption\n");
	cipher = squareAndMultiply(message_in, e, n);
	sign = squareAndMultiply(hashed, d, n); // ���ڼ��� ��.
	printf("cipher : %lld\n\n", cipher); // ��ȣȭ�� ���� ���

	printf("**Generate signature\n");
	printf("message's hash value : %lld\n",hashed); // �Է¹��� ���� hash �Լ� �����
	printf("generated signature : %lld\n", sign); // ���ڼ��� �����
	printf("\n\n");

	message_out = squareAndMultiply(cipher, d, n); // ��ȣȭ ������ square and multiply algorithm�� ����Ѵ�.
	// message_out += 1; (�߰����� �޽����� �����ϱ� ���� �ڵ��̱� ������ �ּ�ó���� �Ͽ����ϴ�.)
	printf("**Decryption\n");
	printf("decrypted cipher : %lld\n\n", message_out);

	// Digital Signature Verify
	sprintf(buf2, "%lld", message_out); // ��ȣȭ ������ ��ģ ���� ���
	hash2 = XXH64(buf2, sizeof(buf2) - 1, 0); // ��ȣȭ ��� ������ hash �Լ� ����
	hashed2 = hash2 % n; // compare value with hashed3
	hashed3 = squareAndMultiply(sign, e, n); // compare value with hashed2

	printf("**Verify signature\n");
	printf("received signature value : %lld\n",sign);
	printf("decrypted message's hash value : %lld\n", hashed2);
	printf("verify value from signature : %lld\n", hashed3);

	// hashed2 �� hashed3 �� ���ƾ� ���ڼ����� valid�ϴ�.
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
	ll val = 1; // �ʱⰪ�� 1�� ����
	while (p > 0) { // p���� �������� ��ȯ
		binary[idx++] = p % 2;
		p /= 2;
	}
	for (i = idx - 1; i >= 0; i--) {
		val = ((val % n) * (val % n)) % n; // bit ���� 1,0 ��� square ������ �����Ѵ�.
		if (binary[i] == 1) { 
			val = ((val % n) * (a % n)) % n; // bit ���� 1�� ���, ���� ����� a�� �ѹ� ���Ѵ�.
		}		
	}	
	return val;
}

// �Ű����� ���� �Ҽ����� �ƴ��� �Ǻ��ϴ� �Լ�.
ll isPrime(ll n)
{
	if (n <= 1 || n == 4) return -1;
	if (n <= 3) return 1;

	ll d = n - 1;
	while (d % 2 == 0)
		d /= 2;

	for (int i = 0; i < 20; i++)
		if (millerRabinTest(d, n) == -1)
			return -1; // -1 : �ռ���
	return 1; // 1 : �Ҽ�
}

ll millerRabinTest(ll d, ll n) {
	// 2 ~ n-2 ������ �ִ� ������ ���� ����
	ll a = 2 + rand() % (n - 4);

	// a^d % n
	ll x = squareAndMultiply(a, d, n);

	if (x == 1 || x == n - 1)
		return 1; // �Ҽ�

	while (d != n - 1)
	{
		x = (x * x) % n;
		d *= 2;
		if (x == 1) return -1; // -1 : �ռ���
		if (x == n - 1) return 1; // 1 : �Ҽ�
	}
	// -1 : �ռ���
	return -1;
}

ll modInverse(ll a, ll n) {
	// Extended Euclidean Algorithm�� ����Ͽ����ϴ�.
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
