#include "commonassignmentfiles.h"

int main(int argc,char *argv[])
{
  char *srcfilename = NULL;
  unsigned char *plainText,*cipherText;
  FILE *srcFile,*destFile;

  if ( argc != 3 || ( !strcmp(argv[1],"-l") && !strcmp(argv[1],"-d") ) )                   //incorrect invocation
  {
    printf("Incorrect arguments supplied - Use [-d] [-l] <filename>\n");
    exit(0);
  }

  srcfilename = argv[2];
  srcFile = fopen(srcfilename,"r");      //open file
  if(srcFile == NULL)           //file not found
  {
    printf("File not found");
    exit(0);
  }

  char *saveStringName = malloc(strlen(srcfilename));     //save source file name
  strcpy(saveStringName,srcfilename);
  strcat(srcfilename,".uf");                // destination file if source is successfully found
    
  if(access( srcfilename , F_OK ) != -1 )       //destination encrypted file already exists
  {
    printf("\nThe file has been encrypted already");
    return -1;
  }

  // The first two lines of the encrypted file will hold the salt value and its length respectively

  destFile = fopen(srcfilename,"w+");
  char *salt = fetchSaltForPassword(); 
  fprintf(destFile, "%s\n", salt );               // write salt value

  PrepareForCryptoOperation(salt);    //common functionalities including initializing the handle and setting the passkey

  int outputSize,bytesTotalWritten = 0;
  plainText = malloc( 1024 );     //read block of 1024 bytes
  cipherText = malloc( 1024 );     // write block of 1024 bytes

  fseek(destFile,128,SEEK_SET);     // set encrypted data to write 128 bytes onwards

  int i = 0; 
  unsigned char c;
  do
  {
    c = fgetc(srcFile);
    if( i == (1024-1) )       // if buffer is full, encrypt and write to file
    {
      libgcryptError =  gcry_cipher_encrypt( handle, cipherText, 1024, plainText, 1024 );    //encrypt
      if (libgcryptError)
      {
        printf ("Failure in encrypting : Details -  %s\n",gcry_strerror (libgcryptError));
        return -1;
      }
      fwrite( cipherText , strlen(cipherText) , 1 , destFile );    //write to encrypted file
      outputSize = (int)strlen(cipherText);
      bytesTotalWritten =  outputSize + bytesTotalWritten; 
      printf("\n Read %d bytes, wrote bytes %d", (int)strlen(plainText), outputSize );
      i=0;
    }
    if( feof(srcFile) )     // if eof , write to file and break out
    {
      plainText[i] = '\0';
      libgcryptError =  gcry_cipher_encrypt( handle, cipherText, 1024, plainText, strlen(plainText) );    //encrypt
      if (libgcryptError)
      {
        printf ("Failure in encrypting : Details -  %s\n",gcry_strerror (libgcryptError));
        return -1;
      }
      fwrite( cipherText , strlen(cipherText) , 1 , destFile );    //write to encrypted file
      outputSize = (int)strlen(cipherText);
      bytesTotalWritten =  outputSize + bytesTotalWritten; 
      printf("\n Read %d bytes, wrote bytes %d", (int)strlen(plainText), outputSize );
      break ;
    }
    plainText[i++] = c;
  }while(1);


  printf("\nSuccessfully encrypted file %s to %s ( %d bytes written)\n\n",saveStringName,srcfilename,bytesTotalWritten);
  
  fclose(destFile);   // close both files
  fclose(srcFile);

  free(plainText);
  free(cipherText);

  PrepareForHashOperation();
  AttachHash(bytesTotalWritten,srcfilename);

  cleanup();       
    
}

void AttachHash( int bytesTotalWritten , char * encryptedFileName )
{
  int hashSize;
  FILE * reader = fopen(encryptedFileName,"r");     // will read the encrypted data
  if(reader ==  NULL)
  {
    printf("\nFailed to open encrypted file to read data");
    exit(0);
  }
    
  FILE * writer = fopen(encryptedFileName,"a");    // will insert hash between salt length and encrypted data
  if(reader ==  NULL)
  {
    printf("\nFailed to open encrypted file to write hash");
    exit(0);
  }

  hashSize = gcry_md_get_algo_dlen( GCRY_MD_SHA512 );   // retrieve hash size

  unsigned char *encryptedData = malloc( bytesTotalWritten );
  unsigned char *digest = malloc( hashSize );           // 512 bit hash

  fseek(writer, 32 , SEEK_SET);        //writer will write the hashed data from 32 to 96 bytes
  fseek(reader, 128, SEEK_SET);                  // reader will begin from the start of encrypted data location

  while( !feof(reader) )         // read the encrypted data
  {    
    fread( encryptedData, bytesTotalWritten, 1, reader );   // read all the encrypted data
    gcry_md_write( digestHandle, encryptedData , strlen(encryptedData) );              // write a hash
    digest = gcry_md_read( digestHandle , GCRY_MD_SHA512 );                     // read it into digest
    fwrite( digest, (int)strlen(digest), 1 , writer);             // write digest to encrypted file
  }

  fclose(writer);
  free(encryptedData);
//  free(digest);

  printf("\nHash written to file of size %d bytes\n",(int)strlen(digest));
}










