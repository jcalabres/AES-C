#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define ROTL8(x,shift) ((uint8_t ) ((x) << (shift)) | ((x) >> (8 - (shift))))

//AES-128 NK=4;NR=10
//AES-192 NK=6;NR=12
//AES-256 NK=8;NR=14
int Nk=4;
int Nr=10;
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
 * Print a State matrix like.
 * @param words: Array of 4 words.
 */
void PrintState(uint8_t words[4][4]){
	printf("[STATE]\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%x",words[i][j]);
		}
		printf("\n");
	}
}

/*
 * Add the subkey to the state matrix.
 * @param state: The state matrix.
 * @param expanded: The state applied with the subkey.
 */
void AddRoundKey(uint8_t state[4][4],uint8_t expanded[(Nr+1)*4][4]){
  for(int i=0;i<4;i++){
    for(int j=0;j<4;j++){
			state[i][j]^=expanded[i][j];
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

void Cipher(uint8_t in[4][4], uint8_t out[4][4], uint8_t expanded[Nr+1][4]){
  uint8_t state[4][4];
  memcpy(state,in,4*4);
  AddRoundKey(state,expanded);
  //uint8_t word[4]={0x09,0xcf,0x4f,0x3c};
  //RotWord(word);
  return;
};

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
  return 0;
};
