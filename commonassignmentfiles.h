#include<stdio.h>
#include<gcrypt.h>
#include<string.h>
#include<unistd.h>

char * requestPassword();
void cleanup(FILE *, FILE * , unsigned char * ,unsigned char * );
void PrepareForCryptoOperation( char *);
void AttachHash(FILE * , int );

gcry_cipher_hd_t handle;
gcry_md_hd_t digestHandle;
gcry_error_t libgcryptError = 0;
int gcryptInitStatus,currentAlgoBlockSize;
char *password,*keybuffer = NULL;


char * fetchSaltForPassword()
{
  return "hamzakarachi";
}

void PrepareForHashOperation()
{
  libgcryptError = gcry_md_open(&digestHandle, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
  if (libgcryptError)
  {
    printf ("Failure in creating MAC handle: Details - %s\n", gcry_strerror (libgcryptError));
    exit(0);
  }

  libgcryptError = gcry_md_setkey(digestHandle, keybuffer, strlen(keybuffer));
  if (libgcryptError)
  {
    printf ("Failure in setting key for MAC: Details - %s\n", gcry_strerror (libgcryptError));
    exit(0);
  }
}

void PrepareForCryptoOperation(char *saltValue)
{
  keybuffer = malloc(256);     
  char *salt = fetchSaltForPassword();

  if( !InitializeGcrypt() )     //initializing gcrypt
  {
    printf("Failed to InitializeGcrypt");
    exit(0);
  }

  libgcryptError = gcry_cipher_open (&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC,0);    //create handle
  if (libgcryptError)
  {
    printf ("Failure in creating encryption handle: Details - %s\n", gcry_strerror (libgcryptError));
    exit(0);
  }

  password = requestPassword();   
  
  libgcryptError = gcry_kdf_derive(password,strlen(password),GCRY_KDF_PBKDF2 ,GCRY_MD_SHA512, salt , 16 , 64000, 64 ,keybuffer );
  if (libgcryptError)
  {
    printf ("Failure in deriving key: Details -  %s\n",gcry_strerror (libgcryptError));
    exit(0);
  }

  libgcryptError = gcry_cipher_setkey (handle, keybuffer, 16);          //set key to encrypt
  if (libgcryptError)
  {
    printf ("Failure in setting key: Details -  %s\n",gcry_strerror (libgcryptError));
    exit(0);
  }

}

void cleanup( FILE *srcFile, FILE * destFile , unsigned char * plainText , unsigned char * cipherText )
{
    fclose(destFile);   //close both files
    fclose(srcFile);
    gcry_cipher_close(handle);
    gcry_md_close(digestHandle);
    free(plainText);
    free(cipherText);
}

char * requestPassword()
{
  char *pwd = (char *)malloc(1024);
  printf("\nPassword : \t");
  scanf("%s",pwd);
  return pwd;
}

int InitializeGcrypt()
{
  if (!gcry_check_version (GCRYPT_VERSION))               //version check
  {
    printf("Version Error\n");
    return 0;
  }
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);           // suspend warnings
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);         // allocate secure memory
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);            // allow warnings
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);    // signal that we are done

  return 1;
}