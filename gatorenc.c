#include "commonassignmentfiles.h"

int main(int argc,char *argv[])
{
  char *srcfilename = NULL;
  unsigned char *plainText,*cipherText;
  FILE *srcFile,*destFile;

  if ( argc != 3 || ( !strcmp(argv[2],"-l") && !strcmp(argv[2],"-d") ) )                   //incorrect invocation
  {
    printf("Incorrect arguments supplied - Use <filename> [-d] [-l]\n");
    return -1;
  }

  srcfilename = argv[1];
  srcFile = fopen(srcfilename,"r");      //open file
  if(srcFile == NULL)           //file not found
  {
    printf("File not found");
    return -1;
  }

  char *saveStringName = malloc(strlen(srcfilename));
  strcpy(saveStringName,srcfilename);
  strcat(srcfilename,".uf");                // destination file if source is successfully found
    
  if(access( srcfilename , F_OK ) != -1 )       //destination encrypted file already exists
  {
    printf("\nThe file has been encrypted already");
    return -1;
  }

  destFile = fopen(srcfilename,"w");
  char *salt = fetchSaltForPassword(); 
  fprintf(destFile, "%d", (int)strlen(salt) );    //write salt length
  fprintf(destFile, "\n%s", salt );               // write salt value

  PrepareForCryptoOperation(salt);    //common functionalities including initializing the handle and setting the passkey

  currentAlgoBlockSize = (int)gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES);  // get the block size of the algo
  if(!currentAlgoBlockSize)
  {
    printf("\nFailed to retrieve block size");
    return -1;
  }

  int outputSize,bytesTotalWritten = 0;
  plainText = (unsigned char*)malloc(sizeof(unsigned char) * 1024);     //read block of 1024 bytes
  cipherText = (unsigned char*)malloc(sizeof(unsigned char) * 1024);     

  fseek(destFile,256,SEEK_SET);
  while(!feof(srcFile))
  {
    fread(plainText,currentAlgoBlockSize,1,srcFile);      // reading in algo block size quantity     
     
    libgcryptError =  gcry_cipher_encrypt (handle, cipherText, 1024, plainText, currentAlgoBlockSize );    //encrypt
    if (libgcryptError)
    {
      printf ("Failure in encrypting : Details -  %s\n",gcry_strerror (libgcryptError));
      return -1;
    }

    fwrite(cipherText,currentAlgoBlockSize,1,destFile);    //write to encrypted file
    outputSize = (int)strlen(cipherText);
    bytesTotalWritten =  outputSize + bytesTotalWritten; 

    printf("\n Read %d bytes, wrote bytes %d", currentAlgoBlockSize, outputSize );

  }
  printf("\nSuccessfully encrypted file %s to %s ( %d bytes written)\n\n",saveStringName,srcfilename,bytesTotalWritten);
  fseek(destFile,128,SEEK_SET);
  fprintf(destFile,"%d",bytesTotalWritten);
  AttachHash(destFile,bytesTotalWritten);

  cleanup( srcFile , destFile , plainText , cipherText );       
    
}

void AttachHash(FILE * encryptedFile , int bytesTotalWritten)
{
  FILE * writer = encryptedFile;

  unsigned char *encryptedData = malloc(bytesTotalWritten);
  unsigned char *digest = malloc(bytesTotalWritten);

  fseek(writer, 256 + bytesTotalWritten, SEEK_SET);   //writer will write the hashed data at the end of file
  fseek(encryptedFile,256,SEEK_SET);                  // reader will begin from the start of encrypted data

  while( fread( encryptedData,bytesTotalWritten,1,encryptedFile) !=0 )
  {
    gcry_md_write( digestHandle, encryptedData , 1);
    digest = gcry_md_read( digestHandle , 0 );
    fwrite( digest, (int)strlen(digest), 1 , writer);
  }

  free(encryptedData);
  free(digest);

  printf("\nHash written to file of size %d bytes",(int)strlen(digest));
}










