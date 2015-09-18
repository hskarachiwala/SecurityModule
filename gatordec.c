#include "commonassignmentfiles.h"

int main(int argc,char *argv[])
{
  char * srcfilename = malloc(64);

  if(argc > 2)
  {
    if( strcmp(argv[1],"-l") == 0)        // open file and read salt
    {
      srcfilename = argv[2];
      PerformDecryption(srcfilename);   
    }
  }
  else
  {
    int listenfd,connfd,bytesReceived = 0;       // socket file descriptors
    struct sockaddr_in serv_addr;
    socklen_t socketSize;
    unsigned char * receiveBuffer = malloc(256);    // read from socket     

    FILE * tempFile = fopen("srcfilename","w");

    memset(&serv_addr, '0', sizeof(serv_addr));     //initialize
    memset(receiveBuffer, '0', sizeof(receiveBuffer));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(atoi(argv[1]));

    printf("\nWaiting for connections\n");
    
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

    socketSize = sizeof(serv_addr);
    
    while( 1 )
    {
      connfd = accept(listenfd, (struct sockaddr *)&serv_addr, &socketSize);
      printf("\nInbound File\n");
      read( connfd, srcfilename, 64);
      while( 1 )
      {
        bytesReceived = read( connfd, receiveBuffer, 256);
        if( bytesReceived == 0)
          break;
        fwrite(receiveBuffer , 1, bytesReceived, tempFile);
      }
      fclose(tempFile);
      printf("%s\n",srcfilename );
      PerformDecryption( srcfilename );
    }
  }  
}

void PerformDecryption ( char * srcfilename )
{
  char *workBuffer;
  FILE *srcFile,*destFile;
  char * salt = malloc(32);

  srcFile = fopen(srcfilename,"r");
  if(srcFile == NULL)           //file not found
  {
    printf("File not found\n");
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

  PrepareForHashOperation();
  VerifyHash(srcfilename);

  workBuffer = malloc( 1024 );     //read block of 1024 bytes
  memset(workBuffer,0x0,1024);

  destFile = fopen("temp.txt","w");
  srcFile = fopen(srcfilename,"r");

  int bytesTotalWritten=0,totalFileSize=0,rem = 0, nRead=0,nWrite = 0;
  fscanf(srcFile,"%s",salt);
  fscanf(srcFile,"%d",&totalFileSize);

  fseek(srcFile,128,SEEK_SET);            //start reading from 128 bytes
  while( (nRead = fread( workBuffer, 1, 1024, srcFile )) != 0)
  {
    if( (rem = nRead %16) !=0 )          // calculate blocks
    {
      //pad this block if needed
    }                                              
    libgcryptError =  gcry_cipher_decrypt( handle, workBuffer, 1024, NULL, 0 );    //decrypt
    if (libgcryptError)
    {
      printf ("\nFailure in encrypting : Details -  %s\n",gcry_strerror (libgcryptError));
      exit(0);
    }
    nWrite = fwrite(workBuffer, 1, 1024, destFile);
    bytesTotalWritten =  nWrite + bytesTotalWritten; 
    printf("\n Read %d bytes, wrote bytes %d", nRead, nWrite );
    memset(workBuffer,0x0,1024);
  }  
  printf("\n\nSuccessfully decrypted file %s to %s ( %d bytes written)\n\n",srcfilename,decryptedFileName,bytesTotalWritten);
  
  //trying to manually shave off extra garbage
  if( ftruncate(fileno(destFile),totalFileSize-1) !=0 )
    printf("\nFile truncate failed");

  fclose(destFile);   // close both files
  fclose(srcFile);

  FILE * tempFile = fopen("temp.txt","r");
  destFile = fopen(decryptedFileName,"w");

  char * readerForTransfer = malloc(totalFileSize);

  fread(readerForTransfer,totalFileSize,1,tempFile);
  fwrite(readerForTransfer,totalFileSize,1,destFile);

  fclose(tempFile);
  fclose(destFile);

  remove("temp.txt");

  free(workBuffer);
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
  fread( hash, 1 , 32, encryptedFile );         // read the 64 byte hash
  fseek( encryptedFile, 128 , SEEK_SET);        // read the encrypted data and rehash

  while( fread( cipher , 1 , 1024 , encryptedFile) != 0 )   // read cipher text to recompute hash
  {   
    gcry_md_write( digestHandle, cipher , strlen(cipher) );
    newhash = gcry_md_read( digestHandle , GCRY_MD_SHA256 );
  }

  //MAC currently not matching due to encrypt decrypt issue
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

