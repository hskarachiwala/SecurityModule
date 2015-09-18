#include "commonassignmentfiles.h"

int main(int argc,char *argv[])
{
  char *srcfilename = NULL;
  char *workBuffer = NULL;
  FILE *srcFile,*destFile;
  char ip[16];
  char port[4];

  if ( argc < 3 || ( !strcmp(argv[1],"-l") && !strcmp(argv[1],"-d") ) )                   //incorrect invocation
  {
    printf("\nIncorrect arguments supplied - Use [[-d ipAddress] | [-l]] <filename>\n");
    exit(0);
  }

  if( !strcmp(argv[1],"-d") )
    srcfilename = argv[3];
  else
    srcfilename = argv[2];

  srcFile = fopen(srcfilename,"r");      //open file
  if(srcFile == NULL)           //file not found
  {
    printf("\nFile not found\n");
    exit(0);
  }

  char *saveStringName = malloc(strlen(srcfilename));     //save source file name
  strcpy(saveStringName,srcfilename);
  strcat(srcfilename,".uf");                // destination file if source is successfully found
    
  if(access( srcfilename , F_OK ) != -1 )       //destination encrypted file already exists
  {
    printf("\nThe file has been encrypted already\n");
    exit(0);
  }

  // The first two lines of the encrypted file will hold the salt value and its length respectively

  destFile = fopen(srcfilename,"w+");
  unsigned char *salt = fetchSaltForPassword(); 
  fprintf(destFile, "%s\n", salt );               // write salt value

  PrepareForCryptoOperation(salt);    //common functionalities including initializing the handle and setting the passkey

  workBuffer = malloc( 1024 );     //read block of 1024 bytes
  memset(workBuffer,0x0,1024);

  fseek(destFile,128,SEEK_SET);     // set encrypted data to write 128 bytes onwards
  
  int bytesTotalWritten=0,totalFileSize=0,rem = 0, nRead=0,nWrite = 0;
  while( (nRead = fread( workBuffer, 1, 1024, srcFile )) != 0)
  {                                              
    libgcryptError =  gcry_cipher_encrypt( handle, workBuffer, 1024, NULL, 0 );    //encrypt
    if (libgcryptError)
    {
      printf ("\nFailure in encrypting : Details -  %s\n",gcry_strerror (libgcryptError));
      exit(0);
    }
    nWrite = fwrite(workBuffer, 1, 1024, destFile);
    totalFileSize = nRead + totalFileSize;
    bytesTotalWritten =  nWrite + bytesTotalWritten; 
    printf("\n Read %d bytes, wrote bytes %d", nRead, nWrite );
    memset(workBuffer,0x0,1024);
  }
  printf("\n\nSuccessfully encrypted file %s to %s ( %d bytes written)\n\n",saveStringName,srcfilename,bytesTotalWritten);
  
  rewind(destFile);
  char firstLine[64];
  fscanf(destFile,"%s",firstLine);
  fprintf(destFile,"\n%d\n", totalFileSize );
  fclose(destFile);   // close both files
  fclose(srcFile);

  free(workBuffer);

  PrepareForHashOperation();
  AttachHash(bytesTotalWritten,srcfilename);

  cleanup();       

  if( strcmp(argv[1],"-d") == 0 )     //send the file over the socket
  {
    SplitIpAddress( ip , port , argv[2] );
    char * srcFileNameToSend = malloc(64);
    memset(srcFileNameToSend , '\0' ,64);
    SendFileContents( srcfilename , ip , port );  
  }
    
}

void SendFileContents( char * srcfilename , char * ip, char * port )
{
  int sockfd = 0;               // socket fd   
  int bytesReceived = 0;    
  unsigned char * sendBuffer = malloc(256); 
  struct sockaddr_in serv_addr;
  memset(sendBuffer, '0', 256);

  serv_addr.sin_family = AF_INET;           //initiatialize serv_addr
  serv_addr.sin_port = htons(atoi(port));           // port
  serv_addr.sin_addr.s_addr = inet_addr(ip);     //localhost

  if(( sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)       // create socket
  {
    printf("\nError : Could not create socket\n");
    exit(0);
  }

  if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0 )   //connect to gatordec
  {
    printf("\nError : Connection to decryption module failed\n");
    exit(0);   
  }

  int n = 0;
  FILE * encryptedFile = fopen(srcfilename, "r"); 
  if(encryptedFile == NULL)
  {
    printf("\nEncrypted File could not be opened\n");
    exit(0);
  }

  write( sockfd, srcfilename, 64  );  // send the filename first
  while(!feof(encryptedFile))
  {
    n = fread( sendBuffer , 1 , 256 ,encryptedFile);    // read one byte and send at a time
    if(n > 0)
      write( sockfd, sendBuffer, n );
  }
  printf("\nTransmitting to %s:%s\n",ip,port);
}

void AttachHash( int bytesTotalWritten , char * encryptedFileName )
{
  int hashSize;
  FILE * reader = fopen(encryptedFileName,"r");     // will read the encrypted data
  if(reader ==  NULL)
  {
    printf("\nFailed to open encrypted file to read data\n");
    exit(0);
  }
    
  FILE * writer = fopen(encryptedFileName,"a");    // will insert hash between salt length and encrypted data
  if(reader ==  NULL)
  {
    printf("\nFailed to open encrypted file to write hash\n");
    exit(0);
  }

  hashSize = gcry_md_get_algo_dlen( GCRY_MD_SHA256 );   // retrieve hash size

  char *encryptedData = malloc( bytesTotalWritten );
  char *digest = malloc( hashSize );           // 512 bit hash

  fseek(writer, 32 , SEEK_SET);        //writer will write the hashed data from 32 to 96 bytes
  fseek(reader, 128, SEEK_SET);                  // reader will begin from the start of encrypted data location

  while( fread( encryptedData, 1, bytesTotalWritten, reader ) !=0 )         // read the encrypted data
  {    
    gcry_md_write( digestHandle, encryptedData , strlen(encryptedData) );              // write a hash
    digest = gcry_md_read( digestHandle , GCRY_MD_SHA256 );                     // read it into digest
    fwrite( digest, 1 , 32 , writer);             // write digest to encrypted file
  }

  fclose(writer);
  free(encryptedData);
 // free(digest);           weird this fails

//  printf("\nHash written to file of size %d bytes\n",(int)strlen(digest));
}










