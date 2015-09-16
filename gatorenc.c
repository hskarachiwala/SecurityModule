#include "commonassignmentfiles.h"

int main(int argc,char *argv[])
{
  char *srcfilename = NULL;
  unsigned char *plainText,*cipherText;
  FILE *srcFile,*destFile;

  if ( argc < 3 || ( !strcmp(argv[1],"-l") && !strcmp(argv[1],"-d") ) )                   //incorrect invocation
  {
    printf("Incorrect arguments supplied - Use [[-d ipAddress] | [-l]] <filename>\n");
    exit(0);
  }

  if( !strcmp(argv[1],"-d") )
    srcfilename = argv[3];
  else
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
  plainText = malloc( 128 );     //read block of 1024 bytes
  cipherText = malloc( 128 );     // write block of 1024 bytes

  fseek(destFile,128,SEEK_SET);     // set encrypted data to write 128 bytes onwards

  int i = 0; 
  unsigned char c;
  do
  {
    c = fgetc(srcFile);
    if( i == (128-1) )       // if buffer is full, encrypt and write to file
    {
      libgcryptError =  gcry_cipher_encrypt( handle, cipherText, 128, plainText, 128 );    //encrypt
      if (libgcryptError)
      {
        printf ("Failure in encrypting : Details -  %s\n",gcry_strerror (libgcryptError));
        return -1;
      }
      fwrite( cipherText , 128 , 1 , destFile );    //write to encrypted file  
      outputSize = (int)strlen(cipherText);
      bytesTotalWritten =  outputSize + bytesTotalWritten; 
      printf("\n Read %d bytes, wrote bytes %d", (int)strlen(plainText), outputSize );
      i=0;
    }
    if( feof(srcFile) )     // if eof , write to file and break out
    {
      plainText[i] = '\0';
      libgcryptError =  gcry_cipher_encrypt( handle, cipherText, 128, plainText, 128 );    //encrypt
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

  if( strcmp(argv[1],"-d") == 0 )     //send the file over the socket
  {
    SendFileContents( srcfilename );  
  }
    
}

void SendFileContents( char * srcfilename )
{
  int sockfd = 0;               // socket fd   
  int bytesReceived = 0;    
  unsigned char * sendBuffer = malloc(256); 
  struct sockaddr_in serv_addr;
  memset(sendBuffer, '0', 256);

  serv_addr.sin_family = AF_INET;           //initiatialize serv_addr
  serv_addr.sin_port = htons(8888);           // port
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");     //localhost

  if(( sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)       // create socket
  {
    printf("\n Error : Could not create socket");
    exit(0);
  }

  if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0 )   //connect to gatordec
  {
    printf("\n Error : Connection to decryption module failed");
    exit(0);   
  }

  int n = 0;
  FILE * encryptedFile = fopen(srcfilename, "r"); 
  if(encryptedFile == NULL)
  {
    printf("Encrypted File could not be opened");
    exit(0);
  }

  while(!feof(encryptedFile))
  {
    n = fread( sendBuffer , 1 , 256 ,encryptedFile);    // read one byte and send at a time
    if(n > 0)
      write( sockfd, sendBuffer, n );
  }
  printf("\nTransmitting to 127.0.0.1:8888");
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

//  printf("\nHash written to file of size %d bytes\n",(int)strlen(digest));
}










