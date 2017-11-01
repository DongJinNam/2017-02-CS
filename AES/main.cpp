#include <iostream>
#include <fstream>
#include <string>
#include "AESManager.h"

using namespace std;

// AES Encryption Mix Columns 연산에서 사용할 Matrix
static unsigned char MixColMat[16] = {
	0x02,0x01,0x01,0x03,
	0x03,0x02,0x01,0x01,
	0x01,0x03,0x02,0x01,
	0x01, 0x01,0x03,0x02
};

// AES Decryption Mix Columns 연산에서 사용할 Matrix
static unsigned char InvMixColMat[16] = {
	0x0E,0x09,0x0D,0x0B,
	0x0B,0x0E,0x09,0x0D,
	0x0D,0x0B,0x0E,0x09,
	0x09,0x0D,0x0B,0x0E
};

static unsigned short irreducible = 0x014D;

static void print(AESManager *manager, int sel) {
	for (int i = 0; i < 16; i++) {
		int val = sel == 0 ? (int)manager->getPlain(i) : (int)manager->getKey(i);
		cout.setf(ios::uppercase);
		cout << std::hex << val / 16 << std::hex << val % 16 << " ";
	}
	cout << "\n";
}

int main() {	
	unsigned char in;
	ifstream keyFile("key.bin",std::ifstream::in); // key.bin
	ifstream plainFile("plain.bin", std::ifstream::in); // plain.bin
	ofstream cipherFile; // cipher.bin
	ofstream decryptFile; // decrypt.bin
	AESManager *manager = new AESManager(irreducible);
	int i = 0;
		
	// file read
	if (keyFile.is_open()) {		
		i = 0;
		while (keyFile.good()) {
			in = keyFile.get();
			manager->InitializeKeyIndex(i, in);
			i++;
		}
		keyFile.close();
	}
	if (plainFile.is_open()) {
		i = 0;
		while (plainFile.good()) {
			in = plainFile.get();
			manager->InitializePlainIndex(i, in);
			i++;
		}
		plainFile.close();
	}
	cipherFile.open("cipher.bin", ios::out | ios::binary);
	decryptFile.open("decrypt.bin", ios::out | ios::binary);

	// setting inverse s_box
	manager->setInverseSBox();

	// Matrix set up
	manager->setMixColMat(MixColMat, 16);
	manager->setInverseMixColMat(InvMixColMat, 16);

	// key expansion
	manager->setKeyExpansion();

	cout << "RC : ";
	for (int i = 0; i < 10; i++) {
		int val = (int)manager->getRC(i);
		cout.setf(ios::uppercase);
		cout << std::hex << val / 16 << std::hex << val % 16 << " ";
	}
	cout << "\nPLAIN : ";
	print(manager, 0);
	cout << "KEY : ";
	print(manager, 1);
	cout << "\n";
	cout << "<------ ENCRYPTION ------>\n\n";
	cout << "KEY EXPANSION\n";

	for (int i = 0; i < 11; i++) {
		cout << "ROUND " << std::dec << i << ": ";
		for (int j = 0; j < 16; j++) {
			int val = (int)manager->getExpandedKey(i * 16 + j);
			cout.setf(ios::uppercase);
			cout << std::hex << val / 16 << std::hex << val % 16 << " ";
		}
		cout << "\n";
	}
	cout << "\n";
	cout << "Round " << std::dec << 0 << "\n";
	manager->addRoundKey(0);
	cout << "AR: ";
	print(manager, 0);
	cout << "\n";

	// encryption
	for (int i = 1; i <= 10; i++) {
		cout << "Round " << std::dec << i << "\n";
		manager->subByte(i);
		cout << "SB: ";
		print(manager, 0);
		manager->shiftRows(i);
		cout << "SR: ";
		print(manager, 0);

		// mix col 연산은 마지막 라운드는 제외한다.
		if (i < 10) {
			manager->mixCols(i);
			cout << "MC: ";
			print(manager, 0);
		}

		manager->addRoundKey(i);
		cout << "AR: ";
		print(manager, 0);
		cout << "\n";
	}
	cout << "CIPHER : ";
	print(manager, 0);

	// cipher.bin write
	if (cipherFile.is_open()) {
		for (int i = 0; i < 16; i++)
			cipherFile << manager->getPlain(i);
		cipherFile.close();
	}

	cout << "\n\n<------ DECRYPTION ------>\n\n";
	// decryption
	cout << "Round " << std::dec << 0 << "\n";
	manager->addRoundKey(10);
	cout << "AR: ";
	print(manager, 0);
	cout << "\n";
	for (int i = 1; i <= 10; i++) {
		cout << "Round " << std::dec << i << "\n";
		manager->inv_shiftRows(i);
		cout << "SR: ";
		print(manager, 0);
		manager->inv_subByte(i);
		cout << "SB: ";
		print(manager, 0);

		manager->addRoundKey(10 - i);
		cout << "AR: ";
		print(manager, 0);
		// inverse mix col 연산도 마지막 라운드는 제외한다.
		if (i < 10) {
			manager->inv_mixCols(i);
			cout << "MC: ";
			print(manager, 0);
		}
		cout << "\n";
	}
	// Decryption 결과 출력
	cout << "DECRYPTED: ";
	print(manager, 0);

	// decrypt.bin write
	if (decryptFile.is_open()) {
		for (int i = 0; i < 16; i++)
			decryptFile << manager->getPlain(i);
		decryptFile.close();
	}		
	return 0;
}