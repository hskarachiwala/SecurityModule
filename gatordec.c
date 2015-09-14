#include "commonassignmentfiles.h"

int main(int argc,char *argv[])
{
  unsigned char *plainText,*cipherText;
  char *srcfilename=NULL;
  FILE *srcFile,*destFile;

  srcfilename = argv[2];
  srcFile = fopen(srcfilename,"r");      //open file
  if(srcFile == NULL)           //file not found
  {
    printf("File not found");
    return -1;
  }
  
  plainText = (unsigned char*)malloc(sizeof(unsigned char) * 1024);     //read block of 1024 bytes
  cipherText = (unsigned char*)malloc(sizeof(unsigned char) * 1024);     

  PrepareForCryptoOperation("hamzakarachi");

  char * decryptedFileName = malloc(256);     // to reconstruct the file name
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

  destFile = fopen(decryptedFileName,"w");     
  currentAlgoBlockSize = (int)gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);  // get the block size of the algo
  if(!currentAlgoBlockSize)
  {
    printf("\nFailed to retrieve block size");
    return -1;
  }

  int outputSize,bytesTotalWritten = 0;
  plainText = (unsigned char*)malloc(sizeof(unsigned char) * 1024);     //read block of 1024 bytes
  cipherText = (unsigned char*)malloc(sizeof(unsigned char) * 1024);     
  
  PrepareForHashOperation();
  VerifyHash(srcFile,cipherText);
  fseek( srcFile, 256 , SEEK_SET);

  while( !feof(srcFile) )
  {      
    fread( cipherText,currentAlgoBlockSize,1,srcFile );
    libgcryptError =  gcry_cipher_decrypt (handle, plainText, 1024, cipherText, currentAlgoBlockSize );    //decrypt
    if (libgcryptError)
    {
      printf ("Failure in decrypting : Details -  %s\n",gcry_strerror (libgcryptError));
      return -1;
    }

    fwrite(plainText,currentAlgoBlockSize,1,destFile);    //write to encrypted file
    outputSize = (int)strlen(cipherText);
    bytesTotalWritten =  outputSize + bytesTotalWritten; 

    printf("\n Read %d bytes, wrote bytes %d", currentAlgoBlockSize, outputSize );

  }
  printf("\nSuccessfully decrypted file %s to %s ( %d bytes written)\n\n",srcfilename,decryptedFileName,bytesTotalWritten);
  cleanup( srcFile , destFile , plainText , cipherText );       

}

void VerifyHash(FILE * encryptedFile , unsigned char * cipherText)
{
  unsigned char *hash = malloc(128);
  unsigned char *newhash = malloc(128);

  fseek( encryptedFile, 128, SEEK_SET);                  // reader will begin from the start of encrypted data
  fread( hash, 128, 1, encryptedFile );
  fseek( encryptedFile, 256 , SEEK_SET);

  while( fread( cipherText,128,1,encryptedFile) !=0 )   // read 128 bytes of cipher text to recompute hash
  {
    gcry_md_write( digestHandle, cipherText , 1);
    newhash = gcry_md_read( digestHandle , 0 );
  }

  if (strcmp(hash,newhash))
  {
    printf("\nMAC successfully verified");
  }
  else
  {
    printf("\nMAC are not matching!");
  }
}