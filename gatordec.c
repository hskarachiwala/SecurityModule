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

  currentAlgoBlockSize = (int)gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES);  // get the block size of the algo
  if(!currentAlgoBlockSize)
  {
    printf("\nFailed to retrieve block size");
    exit(0);
  }

  int outputSize,bytesTotalWritten = 0;
  long filelen;
  PrepareForHashOperation();
  VerifyHash(srcfilename);
  
  srcFile = fopen(srcfilename,"rb");
  destFile = fopen(decryptedFileName,"w");     
  fseek(srcFile, 0, SEEK_END);          // Jump to the end of the file
  filelen = ftell(srcFile);             // Get the current byte offset in the file
  filelen = filelen - 128;              // ignore the first 128 bytes

  plainText = malloc( (filelen + 1) );   // Allocate that much space
  cipherText = malloc( (filelen + 1) );   // Allocate that much space
  cipherText[filelen+1] = '\0';           // Close the string
  fseek( srcFile, 128 , SEEK_SET);          //start reading from 128 bytes in file
  fread( cipherText, filelen , 1, srcFile); // Read in the entire file
      
  libgcryptError =  gcry_cipher_decrypt( handle, plainText, 1024, cipherText, 1024 );    //decrypt
  if (libgcryptError)
  {
    printf ("Failure in encrypting : Details -  %s\n",gcry_strerror (libgcryptError));
    return -1;
  }
    
  fwrite( plainText , strlen(plainText) , 1 , destFile );    //write to decrypted file
  outputSize = (int)strlen(plainText);
  bytesTotalWritten =  outputSize + bytesTotalWritten; 
  printf("\n Read %d bytes, wrote bytes %d", (int)strlen(cipherText), outputSize );
      
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

