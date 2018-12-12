#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define ROTL8(x,shift) ((uint8_t ) ((x) << (shift)) | ((x) >> (8 - (shift))))

//AES-128 NK=4;NR=10
//AES-192 NK=6;NR=12
//AES-256 NK=8;NR=14
int Nk=4;
int Nr=10;
int Nb=4;
//rcon hardcoded values
uint8_t rcon[10]={0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x1b,0x36};

/*
 * Init the sbox.
 * @param sbox: Matrix to store the sbox.
 */
void InitSbox(uint8_t sbox[256]) {
	uint8_t  p = 1, q = 1;
	/* loop invariant: p * q == 1 in the Galois field */
	do {
		/* multiply p by 3 */
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
		/* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;
		/* compute the affine transformation */
		uint8_t  xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
		sbox[p] = xformed ^ 0x63;
	} while (p != 1);
	/* 0 is a special case since it has no inverse */
	sbox[0] = 0x63;
}

/*
 * Applies circular rotation to a word.
 * @param word: The word to be rotated.
 */
void RotWord(uint8_t word[4]){
  uint8_t tmp[4];
  memcpy(tmp,word,4);
  word[3]=tmp[0];
  word[0]=tmp[1];
  word[1]=tmp[2];
  word[2]=tmp[3];
}

/*
 * Applies the sbox to the state matrix.
 * @param state: The state matrix.
 * @param sbox: The sbox matrix.
 */
void SubBytes(uint8_t state[4][4], uint8_t* sbox){
  for(int i=0;i<4;i++){
    for(int j=0;j<4;j++){
      state[i][j]=sbox[state[i][j]];
    }
  }
}

/*
 * Applies the sbox to a word.
 * @param word: A word.
 * @param sbox: The sbox matrix.
 */
void SubWord(uint8_t word[4], uint8_t* sbox){
  for(int i=0;i<4;i++){
    word[i]=sbox[word[i]];
  }
}

/*
 * Shift rows process.
 * @param state: The state to shift.
 */
void ShiftRows(uint8_t state[4][4]){
	uint8_t tmp[4][4];
	memcpy(tmp,state,4*4);
	for(int j=1;j<4;j++){
		for(int i=0;i<4;i++){
			state[i][j]=tmp[(i+j)%4][j];
		}
	}
}

uint8_t GaloisMul(uint8_t a, uint8_t b) {
	uint8_t p = 0;
	uint8_t counter;
	uint8_t hi_bit_set;
	for(counter = 0; counter < 8; counter++) {
		if((b & 1) == 1)
			p ^= a;
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if(hi_bit_set == 0x80)
			a ^= 0x1b;
		b >>= 1;
	}
	return p;
}

void MixColumns(uint8_t state[4][4]){
	uint8_t temp[4][4]={0};
	memcpy(temp,state,4*4);
	for(int i=0;i<4;i++){
		state[i][0]=GaloisMul(temp[i][0],2)^GaloisMul(temp[i][3],1)^GaloisMul(temp[i][2],1)^GaloisMul(temp[i][1],3);
		state[i][1]=GaloisMul(temp[i][1],2)^GaloisMul(temp[i][0],1)^GaloisMul(temp[i][3],1)^GaloisMul(temp[i][2],3);
		state[i][2]=GaloisMul(temp[i][2],2)^GaloisMul(temp[i][1],1)^GaloisMul(temp[i][0],1)^GaloisMul(temp[i][3],3);
		state[i][3]=GaloisMul(temp[i][3],2)^GaloisMul(temp[i][2],1)^GaloisMul(temp[i][1],1)^GaloisMul(temp[i][0],3);
	}
}


/*
 * Add the subkey to the state matrix.
 * @param state: The state matrix.
 * @param expanded: The state applied with the subkey.
 * @rework: adapt to different keys.
 */
void AddRoundKey(uint8_t state[4][4],uint8_t expanded[(Nr+1)*4][4],int i1){
	for(int i=0;i<4;i++){
    for(int j=0;j<4;j++){
			state[i][j]^=expanded[i1+i][j];
		}
  }
}

void KeyExpansion(uint8_t key[Nk][4], uint8_t expanded[(Nr+1)*4][4], uint8_t Nk){
  uint8_t sbox[256]={0};
  InitSbox(sbox);
  uint8_t temp[4]={0};
  memcpy(expanded,key,Nk*4);
  for(int i=Nk;i<4*(Nr+1);i++){
    memcpy(temp,expanded[i-1],4);
    if(i%Nk==0){
      RotWord(temp);
      SubWord(temp,sbox);
      if(i==4){
        temp[0]^=rcon[0];
      }else if(i==8){
        temp[0]^=rcon[1];
      }else if(i==12){
        temp[0]^=rcon[2];
      }else if(i==16){
        temp[0]^=rcon[3];
      }else if(i==20){
        temp[0]^=rcon[4];
      }else if(i==24){
        temp[0]^=rcon[5];
      }else if(i==28){
        temp[0]^=rcon[6];
      }else if(i==32){
        temp[0]^=rcon[7];
      }else if(i==36){
        temp[0]^=rcon[8];
      }else if(i==40){
        temp[0]^=rcon[9];
      }
    }else if(Nk>6 && i%Nk==4){
      SubWord(temp,sbox);
    }
    for(int j=0;j<4;j++){
      expanded[i][j]=expanded[i-Nk][j]^temp[j];
    }
  }
}

/*
 * Print a State matrix like.
 * @param words: Array of 4 words.
 */
void PrintState(uint8_t state[4][4]){
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%x",state[j][i]);
		}
		printf("\n");
	}
}

void Cipher(uint8_t in[4][4], uint8_t out[4][4], uint8_t expanded[(Nr+1)*4][4]){
  uint8_t state[4][4];
  memcpy(state,in,4*4);
	uint8_t sbox[256]={0};
  InitSbox(sbox);
  AddRoundKey(state,expanded,0);
	for(int round=1;round<Nr;round++){
		SubBytes(state,sbox);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state,expanded,round*Nb);
	}
	SubBytes(state,sbox);
	ShiftRows(state);
	AddRoundKey(state,expanded,Nr*Nb);
	memcpy(out,state,4*4);
}

void InvCipher(uint8_t in[4][4], uint8_t out[4][4], uint8_t expanded[(Nr+1)*4][4]){
  uint8_t state[4][4];
  memcpy(state,in,4*4);
	uint8_t sbox[256]={0};
  InitSbox(sbox);
  AddRoundKey(state,expanded,Nr*Nb);
	PrintState(state);

	/*for(int round=1;round<Nr;round++){
		SubBytes(state,sbox);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state,expanded,round*Nb);
	}
	SubBytes(state,sbox);
	ShiftRows(state);
	AddRoundKey(state,expanded,Nr*Nb);
	memcpy(out,state,4*4);*/
}

int main(){
  uint8_t key[4][4]={
    {0x2b,0x7e,0x15,0x16},
    {0x28,0xae,0xd2,0xa6},
    {0xab,0xf7,0x15,0x88},
    {0x09,0xcf,0x4f,0x3c}};
  uint8_t in[4][4]={
    {0x32,0x43,0xf6,0xa8},
    {0x88,0x5a,0x30,0x8d},
    {0x31,0x31,0x98,0xa2},
    {0xe0,0x37,0x07,0x34}};
  uint8_t out[4][4]={0};

  uint8_t expanded[(Nr+1)*4][4];
  KeyExpansion(key,expanded,Nk);
  Cipher(in,out,expanded);

	printf("[INPUT]:\n");
	PrintState(in);
	printf("[OUTPUT]:\n");
	PrintState(out);
  return 0;
};
