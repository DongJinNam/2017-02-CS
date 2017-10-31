#include "AESManager.h"

AESManager::AESManager() 
{
}

AESManager::AESManager(unsigned short val)
{
	round_cnt = 10;

	irreducible = val;
	mapTbl = new unsigned short[16];

	rc = new unsigned char[10];
	origin_key = new unsigned char[16];
	origin_plain = new unsigned char[16];
	s_box = new unsigned char[256];
	inv_s_box = new unsigned char[256];
	expanded_key = new unsigned char[16 * 11];
	mix_col_mat = new unsigned char[16];
	inv_mix_col_mat = new unsigned char[16];
	
	// map table setting
	for (int i = 0; i < 16; i++) {
		mapTbl[i] = (1 << i);
	}

	// rc 초기화 with Galois Field Multiplication
	rc[0] = 0x01;
	for (int i = 1; i < 10; i++) {
		rc[i] = GFMul(rc[i - 1], 0x02);
	}

	// sbox 초기화
	InitializeSBox();
}


AESManager::~AESManager()
{
	if (rc != nullptr) delete[] rc; rc = nullptr;
	if (s_box != nullptr) delete[] s_box; s_box = nullptr;
	if (inv_s_box != nullptr) delete[] s_box; s_box = nullptr;
	if (origin_key != nullptr) delete[] origin_key; origin_key = nullptr;
	if (origin_plain != nullptr) delete[] origin_plain; origin_plain = nullptr;
	if (expanded_key != nullptr) delete[] expanded_key; expanded_key = nullptr;
	if (mix_col_mat != nullptr) delete[] mix_col_mat; mix_col_mat = nullptr;
	if (inv_mix_col_mat != nullptr) delete[] inv_mix_col_mat; inv_mix_col_mat = nullptr;
}

void AESManager::InitializeKeyIndex(int index, unsigned char val)
{
	origin_key[index] = val;
}

void AESManager::InitializePlainIndex(int index, unsigned char val)
{
	origin_plain[index] = val;
}

void AESManager::InitializeSBox()
{	
	unsigned char p = 1, q = 1;
	do {
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		unsigned char xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		s_box[p] = xformed ^ 0x15;
	} while (p != 1);
	s_box[0] = 0x15;	
}

void AESManager::setSBox(int i, unsigned char uc)
{
	s_box[i] = uc;
}

void AESManager::setInverseSBox()
{
	for (int i = 0; i < 256; i++) {
		int r = (int) s_box[i] / 16;
		int c = (int) s_box[i] % 16;
		inv_s_box[r * 16 + c] = (unsigned char) i;
	}
}

void AESManager::setMixColMat(unsigned char mat[], int count)
{
	for (int i = 0; i < count; i++)
		mix_col_mat[i] = mat[i];
}

void AESManager::setInverseMixColMat(unsigned char mat[], int count)
{
	for (int i = 0; i < count; i++)
		inv_mix_col_mat[i] = mat[i];
}

void AESManager::setKeyExpansion()
{
	unsigned char uc_arr[4];
	int cur, i, j, k;
	int round = 0;

	for (i = 0; i < 16; i++) {
		expanded_key[i] = origin_key[i];
	}
	cur = i;

	for (i = 0; i < 10; i++) {
		// round function
		for (j = 0; j < 4; j++) {
			uc_arr[j] = expanded_key[(cur - 4) + (j + 1) % 4];
			uc_arr[j] = s_box[(uc_arr[j] / 16) * 16 + (uc_arr[j] % 16)];
			if (j == 0) uc_arr[j] ^= rc[round++];
		}
		// setting
		for (j = 0; j < 4; j++) {
			for (k = 0; k < 4; k++) {
				expanded_key[cur + k] = uc_arr[k] ^ expanded_key[cur + k - 16];
				uc_arr[k] = expanded_key[cur + k];
			}
			cur += 4;
		}
	}
}

void AESManager::addRoundKey(int round)
{
	for (int i = 0; i < 16; i++)
		origin_plain[i] ^= expanded_key[round * 16 + i];
}

void AESManager::subByte(int round)
{
	for (int i = 0; i < 16; i++) {
		int r = (int) origin_plain[i] / 16;
		int c = (int) origin_plain[i] % 16;
		origin_plain[i] = s_box[r * 16 + c];
	}		
}

void AESManager::shiftRows(int round)
{
	unsigned char uc_arr[4];
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			uc_arr[j] = origin_plain[j * 4 + i];
		}
		for (int j = 0; j < 4; j++) {
			origin_plain[j * 4 + i] = uc_arr[(j + i) % 4];
		}
	}
}

void AESManager::mixCols(int round)
{
	// mix column 을 진행하기 전, 상태를 임시로 저장한다.
	unsigned char temp_arr[16];
	for (int i = 0; i < 16; i++) {
		temp_arr[i] = origin_plain[i];
	}
	for (int i = 0; i < 16; i++) {
		int r = i % 4;
		int c = i / 4;
		unsigned char res = 0x00;
		for (int j = 0; j < 4; j++) {
			unsigned char mul = GFMul(mix_col_mat[r + j * 4], temp_arr[c * 4 + j]);
			res = GFAdd(res, mul);
		}
		origin_plain[i] = res;
	}
}

void AESManager::inv_subByte(int round)
{
	for (int i = 0; i < 16; i++) {
		int r = (int)origin_plain[i] / 16;
		int c = (int)origin_plain[i] % 16;
		origin_plain[i] = inv_s_box[r * 16 + c];
	}
}

void AESManager::inv_shiftRows(int round)
{
	unsigned char uc_arr[4];
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			uc_arr[j] = origin_plain[j * 4 + i];
		}
		for (int j = 0; j < 4; j++) {
			origin_plain[j * 4 + i] = uc_arr[(j +(4 - i)) % 4];
		}
	}
}

void AESManager::inv_mixCols(int round)
{
	// inverse mix column 을 진행하기 전, 상태를 임시로 저장한다.
	unsigned char temp_arr[16];
	for (int i = 0; i < 16; i++) {
		temp_arr[i] = origin_plain[i];
	}
	for (int i = 0; i < 16; i++) {
		int r = i % 4;
		int c = i / 4;
		unsigned char res = 0x00;
		for (int j = 0; j < 4; j++) {
			unsigned char mul = GFMul(inv_mix_col_mat[r + j * 4], temp_arr[c * 4 + j]);
			res = GFAdd(res, mul);
		}
		origin_plain[i] = res;
	}
}

unsigned char AESManager::getRC(int i) {
	return rc[i];
}

unsigned char AESManager::getKey(int i) {
	return origin_key[i];
}

unsigned char AESManager::getExpandedKey(int i)
{
	return expanded_key[i];
}

unsigned char AESManager::getPlain(int i) {
	return origin_plain[i];
}

unsigned char AESManager::getSBox(int i,int j) {
	return s_box[(i << 4) + j];
}

unsigned char AESManager::getRFVal(unsigned char val, int round)
{
	return val ^ rc[round - 1];
}

unsigned char AESManager::GFAdd(unsigned char a, unsigned char b)
{
	return a ^ b;
}

unsigned char AESManager::GFMul(unsigned char a, unsigned char b)
{
	unsigned short res = 0x0000;
	unsigned char ans;
	int start = 0;
	//  Shift and XOR 연산
	for (int i = 0; i < 8; i++) {
		if (b & mapTbl[i]) {
			res ^= (a << i);
		}
	}
	// 왼쪽에서 부터 처음 1인 위치 찾기.
	for (int i = 15; i >= 0; i--) {
		if (res & mapTbl[i]) {
			start = i;
			break;
		}
	}
	// GF 범위를 벗어나는 경우, 다음과 같이 처리.
	if (start >= 8) {
		while (res >= 0x0100) {
			res ^= (irreducible << (start - 8));
			for (int i = start; i >= 0; i--) {
				if (res & mapTbl[i]) {
					start = i;
					break;
				}
			}
		}
	}
	ans = (unsigned char)(res);
	return ans;
}