#include<stdio.h>
#include<gcrypt.h>
#include<string.h>


char * requestPassword();
void cleanup(FILE *srcFile,FILE * destFile,gcry_cipher_hd_t handle,unsigned char * plainText,unsigned char * cipherText);

int main(int argc,char *argv[])
{
  int gcryptInitStatus,currentAlgoBlockSize;
  char *filename,*password = NULL;

  unsigned char *plainText,*cipherText;
  char keybuffer[256];

  FILE *srcFile,*destFile;

  gcry_cipher_hd_t handle;
  gcry_error_t libgcryptError = 0;

  if (argc<2)                   //no filename given
  {
    printf("Missing file name to encrypt\n");
    return -1;
  }

  filename = argv[1];
  srcFile = fopen(filename,"r");      //open file
  if(srcFile == NULL)           //file not found
  {
    printf("File not found");
    return -1;
  }

  if( !InitializeGcrypt() )     //initializing gcrypt
  {
    printf("Failed to InitializeGcrypt");
    return -1;
  }
  
  plainText = (unsigned char*)malloc(sizeof(unsigned char) * 16);     //read 128 bits at a time
  cipherText = (unsigned char*)malloc(sizeof(unsigned char) * 16);     
  
  libgcryptError = gcry_cipher_open (&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC,0);    //create handle
  if (libgcryptError)
  {
    printf ("Failure in creating encryption handle: Details - %s\n", gcry_strerror (libgcryptError));
    return -1;
  }

  password = requestPassword();   
    
  libgcryptError = gcry_kdf_derive(password,strlen(password),GCRY_KDF_PBKDF2 ,GCRY_MD_SHA256, "somesalt" , 8 , 100, 32 ,keybuffer );
  if (libgcryptError)
  {
    printf ("Failure in deriving key: Details -  %s\n",gcry_strerror (libgcryptError));
    return -1;
  }

  libgcryptError = gcry_cipher_setkey (handle, keybuffer,256);          //set key to encrypt
  if (libgcryptError)
  {
    printf ("Failure in setting key: Details -  %s\n",gcry_strerror (libgcryptError));
    return -1;
  }

  destFile = fopen(strcat(filename,".uf"),"w");     
  currentAlgoBlockSize = sizeof(gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256));  // get the block size of the algo
  
  while(!feof(srcFile))
  {
    fread(plainText,currentAlgoBlockSize,1,srcFile);    
     
    libgcryptError =  gcry_cipher_encrypt (handle,cipherText,currentAlgoBlockSize,plainText,currentAlgoBlockSize);    //encrypt
    if (libgcryptError)
    {
      printf ("Failure in encrypting : Details -  %s\n",gcry_strerror (libgcryptError));
      return -1;
    }

    printf(" Plaintext was : %s\n\n  Ciphertext is : %s\n\n",plainText, cipherText);

    fwrite(cipherText,currentAlgoBlockSize,1,destFile);    //write to encrypted file

  }

  cleanup(srcFile,destFile,handle,plainText,cipherText);       
    
}

void cleanup(FILE *srcFile,FILE * destFile,gcry_cipher_hd_t handle,unsigned char * plainText,unsigned char * cipherText)
{
    fclose(destFile);   //close both files
    fclose(srcFile);
    gcry_cipher_close(handle);
    free(plainText);
    free(cipherText);
}

char * requestPassword()
{
  char *pwd = (char *)malloc(1024);
  printf("\nEnter the password \t");
  scanf("%s",pwd);
  return pwd;
}

int InitializeGcrypt()
{
  if (!gcry_check_version (GCRYPT_VERSION))               //version check
  {
    printf("Version Error\n");
    return -1;
  }
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);           // suspend warnings
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);         // allocate secure memory
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);            // allow warnings
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);    // signal that we are done

  return 1;
}









