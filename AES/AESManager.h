#pragma once

#define ROTL8(x,shift) ((unsigned char) ((x) << (shift)) | ((x) >> (8 - (shift))))

class AESManager
{
	int round_cnt;	

	unsigned short irreducible; // irreducible polynomial	
	unsigned short *mapTbl; 

	unsigned char *rc;
	unsigned char *origin_key;
	unsigned char *origin_plain;
	unsigned char *s_box;
	unsigned char *inv_s_box;
	unsigned char *expanded_key;
	unsigned char *mix_col_mat;
	unsigned char *inv_mix_col_mat;

public:
	AESManager();
	AESManager(unsigned short irreducible);
	~AESManager();

	void InitializeKeyIndex(int, unsigned char);
	void InitializePlainIndex(int, unsigned char);
	void InitializeSBox();
	void setSBox(int, unsigned char);
	void setInverseSBox();
	void setMixColMat(unsigned char mat[],int count);
	void setInverseMixColMat(unsigned char mat[], int count);

	
	void setKeyExpansion();
	void addRoundKey(int round);
	void subByte(int round);
	void shiftRows(int round);
	void mixCols(int round);
	void inv_subByte(int round);
	void inv_shiftRows(int round);
	void inv_mixCols(int round);

	unsigned char getRC(int i);
	unsigned char getKey(int i);
	unsigned char getExpandedKey(int i);
	unsigned char getPlain(int i);
	unsigned char getSBox(int i,int j);
	unsigned char getRFVal(unsigned char val, int round);

	unsigned char GFAdd(unsigned char, unsigned char);
	unsigned char GFMul(unsigned char, unsigned char);
};

