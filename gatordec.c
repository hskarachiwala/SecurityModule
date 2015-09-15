#include "commonassignmentfiles.h"

int main(int argc,char *argv[])
{
  unsigned char *plainText,*cipherText;
  char *srcfilename=NULL;
  FILE *srcFile,*destFile;
  char * salt = malloc(16);

  srcfilename = argv[2];
  srcFile = fopen(srcfilename,"r");      //open file
  if(srcFile == NULL)           //file not found
  {
    printf("File not found");
    exit(0);
  }
  
  fscanf(srcFile,"%s",salt);     // fetch salt from encrypted file
  fclose(srcFile);

  PrepareForCryptoOperation(salt);

  char * decryptedFileName = malloc( 64 );     // to reconstruct the file name
  int i;
  for( i = 0 ; i < 256 ; i++)
  {
    if( srcfilename[i] == '.' )
    {
      decryptedFileName[i] = '\0';
      break;
    }
    decryptedFileName[i] = srcfilename[i];
  }
  strcat( decryptedFileName,".txt" );

  int outputSize,bytesTotalWritten = 0;
  PrepareForHashOperation();
  VerifyHash(srcfilename);

  plainText = malloc( 256 );
  cipherText = malloc( 256 );

  destFile = fopen("hamza.txt","w");
  srcFile = fopen(srcfilename,"r");
  fseek(srcFile,128,SEEK_SET);            //start reading from 128 bytes

  while( !feof(srcFile) )
  {      
    fread( cipherText,256,1,srcFile );
    libgcryptError =  gcry_cipher_decrypt (handle, cipherText, 256, NULL, 0 );    //decrypt
    if (libgcryptError)
    {
      printf ("Failure in decrypting : Details -  %s\n",gcry_strerror (libgcryptError));
      return -1;
    }
    fwrite(cipherText,256,1,destFile);    //write to decrypted file
    outputSize = (int)strlen(cipherText);
    bytesTotalWritten =  outputSize + bytesTotalWritten; 

    printf("\n Read %d bytes, wrote bytes %d", 256, outputSize );
  }
  printf("\nSuccessfully decrypted file %s to %s ( %d bytes written)\n\n",srcfilename,decryptedFileName,bytesTotalWritten);
  
  fclose(destFile);   // close both files
  fclose(srcFile);

  free(plainText);
  free(cipherText);
  free(salt);

  cleanup();       
}

void VerifyHash(char * encryptedFileName)
{
  unsigned char * cipher = malloc(1024);
  unsigned char *hash = malloc(64);           // size of hash
  unsigned char *newhash = malloc(64);
  FILE * encryptedFile = fopen(encryptedFileName,"r");

  fseek( encryptedFile, 32, SEEK_SET);                  // reader will begin from the start of encrypted data
  fread( hash, 64 , 1, encryptedFile );         // read the 64 byte hash
  fseek( encryptedFile, 128 , SEEK_SET);        // read the encrypted data and rehash

  while( !feof(encryptedFile) )   // read cipher text to recompute hash
  {
    fread( cipher , 1024 , 1 , encryptedFile);
    gcry_md_write( digestHandle, cipher , strlen(cipher) );
    newhash = gcry_md_read( digestHandle , GCRY_MD_SHA512 );
  }

  if (strcmp(hash,newhash))
  {
    printf("\nMAC successfully verified");
  }
  else
  {
    printf("\nMAC are not matching!");
  }

  free(cipher);
  free(hash);
  //free(newhash);
  fclose(encryptedFile);
}

