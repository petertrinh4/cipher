/*============================================================================
| Assignment: pa02 - Encrypting a plaintext file using the Hill cipher
|
|     Author: Peter Trinh
|   Language: c
| To Compile: gcc -o pa02 pa02.c
| To Execute: c -> ./pa02 kX.txt pX.txt
|             where kX.txt is the keytext file
|             and pX.txt is plaintext file
|       Note:
|             All input files are simple 8 bit ASCII input
|             All execute commands above have been tested on Eustis
|
|      Class: CIS3360 - Security in Computing - Summer 2025
| Instructor: McAlpin
|   Due Date: 7/6/25
+===========================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

int readKeyMatrix(FILE *fp, int matrix[9][9]);
int readPlaintext(FILE *fp, char *buffer);
void padPlaintext(char *text, int *length, int blockSize);
void encryptText(const char *plaintext, int length, int matrix[9][9], int size, char *ciphertext);
void printMatrix(int matrix[9][9], int size);
void printText(const char *label, const char *text, int length);

int main(int argc, char *argv[]) {
    if (argc != 3) { //Forcing the argument count to be only 3
        fprintf(stderr, "Usage: %s keyFile.txt plaintextFile.txt\n", argv[0]);
        return 1;
    }

    printf("\n");

    FILE *keyFile = fopen(argv[1], "r");  //Reads the file containing the key matrix
    if (!keyFile) {
        perror("Error opening key file");
        return 1;
    }

    FILE *plainFile = fopen(argv[2], "r"); //Reads the plaintext file
    if (!plainFile) {
        perror("Error opening plaintext file");
        fclose(keyFile);
        return 1;
    }

    int keyMatrix[9][9]; //Initializing the key matrix
    int keySize = readKeyMatrix(keyFile, keyMatrix);

    char plaintext[10000]; //Max plaintext letters in the file
    int ptLength = readPlaintext(plainFile, plaintext);
    padPlaintext(plaintext, &ptLength, keySize);

    char ciphertext[10000];
    encryptText(plaintext, ptLength, keyMatrix, keySize, ciphertext);

    printf("Key matrix:\n"); //Formatting the output
    printMatrix(keyMatrix, keySize);
    printf("\n");
    printText("Plaintext", plaintext, ptLength);
    printf("\n");
    printText("Ciphertext", ciphertext, ptLength);

    fclose(keyFile); //Closing files after use
    fclose(plainFile);

    return 0;
}

int readKeyMatrix(FILE *fp, int matrix[9][9]) {
    int size;
    fscanf(fp, "%d", &size); //Scans the key file
    if (size < 2 || size > 9) {
        fprintf(stderr, "Invalid key matrix size.\n");
        exit(1);
    }
    for (int i = 0; i < size; i++)
        for (int j = 0; j < size; j++)
            fscanf(fp, "%d", &matrix[i][j]); //Creates the matrix
    return size;
}

int readPlaintext(FILE *fp, char *buffer) {
    int len = 0;
    char ch;
    while ((ch = fgetc(fp)) != EOF) { //Reads the plaintext
        if (isalpha(ch)) {
            buffer[len++] = tolower(ch);
        }
    }
    buffer[len] = '\0';
    return len;
}

void padPlaintext(char *text, int *length, int blockSize) {
    while (*length % blockSize != 0) { //Pads the block with an x to fit the size
        text[(*length)++] = 'x';
    }
    text[*length] = '\0';
}

void encryptText(const char *plaintext, int length, int matrix[9][9], int size, char *ciphertext) {
    int index = 0;
    for (int i = 0; i < length; i += size) { //Using the hill cipher algorithm to encrypt the plaintext
        for (int row = 0; row < size; row++) {
            int sum = 0;
            for (int col = 0; col < size; col++) {
                sum += matrix[row][col] * (plaintext[i + col] - 'a');
            }
            ciphertext[index++] = (sum % 26) + 'a';
        }
    }
    ciphertext[index] = '\0';
}

void printMatrix(int matrix[9][9], int size) {
    for (int i = 0; i < size; i++) { //Prints the matrix
        for (int j = 0; j < size; j++) {
            printf("%4d", matrix[i][j]);
        }
        printf("\n");
    }
}

void printText(const char *label, const char *text, int length) {
    if (label != NULL) printf("%s:\n", label); //Prints the ciphertext
    for (int i = 0; i < length; i++) {
        printf("%c", text[i]);
        if ((i + 1) % 80 == 0) printf("\n");
    }
    printf("\n");
}

/*=============================================================================
| I Peter Trinh (pe408680) affirm that this program is
| entirely my own work and that I have neither developed my code together with
| any another person, nor copied any code from any other person, nor permitted
| my code to be copied or otherwise used by any other person, nor have I
| copied, modified, or otherwise used programs created by others. I acknowledge
| that any violation of the above terms will be treated as academic dishonesty.
+=============================================================================*/