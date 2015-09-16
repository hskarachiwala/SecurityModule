#include "commonassignmentfiles.h"

int main(int argc,char *argv[])
{
  char * srcfilename = malloc(64);

  if(argc > 1)
  {
    if( strcmp(argv[1],"-l") == 0)        // open file and read salt
    {
      srcfilename = argv[2];
      PerformDecryption(srcfilename);   
    }
  }
  else
  {
    srcfilename = "Decrypted.txt.uf";

    int listenfd,connfd,bytesReceived = 0;       // socket file descriptors
    struct sockaddr_in serv_addr;
    socklen_t socketSize;
    unsigned char * receiveBuffer = malloc(256);    // read from socket     

    FILE * tempFile = fopen("srcfilename","w");

    memset(&serv_addr, '0', sizeof(serv_addr));     //initialize
    memset(receiveBuffer, '0', sizeof(receiveBuffer));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(8888);

    if(( listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)       // create socket
    {
      printf("\n Error : Could not create socket");
      exit(0);
    }
    
    if( bind( listenfd, (struct sockaddr*)&serv_addr,sizeof(serv_addr)) == -1)      //bind to address
    {
      printf("\nError occured in socket bind");
      exit(0);
    }
      
    if( listen(listenfd, 10) == -1 )        // listen for connections
    {
      printf("Failed to listen\n");
      exit(0);
    }

    printf("\nWaiting for connections");
    socketSize = sizeof(serv_addr);
    
    while( 1 )
    {
      connfd = accept(listenfd, (struct sockaddr *)&serv_addr, &socketSize);
      printf("\nInbound File");
      while( 1 )
      {
        bytesReceived = read( connfd, receiveBuffer, 256);
        printf("%d\n",bytesReceived );
        if( bytesReceived == 0)
          break;
        fwrite(receiveBuffer , 1, bytesReceived, tempFile);
      }
      fclose(tempFile);
      PerformDecryption( srcfilename );
    }
  }  
}

void PerformDecryption ( char * srcfilename )
{
  unsigned char *plainText,*cipherText;
  FILE *srcFile,*destFile;
  char * salt = malloc(16);

  srcFile = fopen(srcfilename,"r");
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

  plainText = malloc( 128 );
  cipherText = malloc( 128 );

  destFile = fopen("hamza.txt","w");
  srcFile = fopen(srcfilename,"r");
  fseek(srcFile,128,SEEK_SET);            //start reading from 128 bytes

  while( !feof(srcFile) )
  { 
    fread( cipherText,128,1,srcFile );
    libgcryptError =  gcry_cipher_decrypt(handle, plainText, 128, cipherText, 128 );    //decrypt
    if (libgcryptError)
    {
      printf ("Failure in decrypting : Details -  %s\n",gcry_strerror (libgcryptError));
      exit(0);
    }
    fwrite(plainText,128,1,destFile);    //write to decrypted file
    outputSize = (int)strlen(plainText);
    bytesTotalWritten =  outputSize + bytesTotalWritten; 

    printf("\n Read %d bytes, wrote bytes %d", 128 , outputSize );
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
//    printf("\nMAC are not matching!!");
//    exit(0);
  }
  
  free(cipher);
  free(hash);
  //free(newhash);
  fclose(encryptedFile);
}

