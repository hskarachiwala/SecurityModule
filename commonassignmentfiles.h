#include<stdio.h>
#include<gcrypt.h>
#include<string.h>
#include<unistd.h>

char * requestPassword();
void PrepareForHashOperation();
void PrepareForCryptoOperation( char *);
void AttachHash( int , char *);
void VerifyHash( char *);
void cleanup();

gcry_cipher_hd_t handle;              // cipher handle
gcry_md_hd_t digestHandle;            // digest handle
gcry_error_t libgcryptError = 0;      // error codes
int gcryptInitStatus,currentAlgoBlockSize;  
unsigned char *password,*keybuffer = NULL;

/*

Initializing operations

Checking version and allocating secure memory (not being used currently)

*/

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

void PrepareForHashOperation()
{
  libgcryptError = gcry_md_open( &digestHandle, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC );      // using sha512 as the hash, and requesting hmac
  if (libgcryptError)
  {
    printf ("Failure in creating MAC handle: Details - %s\n", gcry_strerror (libgcryptError));
    exit(0);
  }

  libgcryptError = gcry_md_setkey( digestHandle, keybuffer, strlen(keybuffer));      // using the same key 128 bits 
  if (libgcryptError)
  {
    printf ("Failure in setting key for MAC: Details - %s\n", gcry_strerror (libgcryptError));
    exit(0);
  }
}

void PrepareForCryptoOperation(char *saltValue)
{
  keybuffer = malloc(128);        // key size is 128 bits     
  password = requestPassword();   

  if( !InitializeGcrypt() )     //initializing gcrypt
  {
    printf("Failed to InitializeGcrypt");
    exit(0);
  }

  libgcryptError = gcry_cipher_open( &handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS) ;    //create handle
  if (libgcryptError)
  {
    printf ("Failure in creating encryption handle: Details - %s\n", gcry_strerror (libgcryptError));
    exit(0);
  }

  libgcryptError = gcry_cipher_setiv (handle, "thissixteenbytes" , 16 );   // set an iv for cbc
  if (libgcryptError)
  {
    printf ("Failure in setting the IV for encryption : Details - %s\n", gcry_strerror (libgcryptError));
    exit(0);
  }
  
  libgcryptError = gcry_kdf_derive( password , strlen(password), GCRY_KDF_PBKDF2 , GCRY_MD_SHA512, saltValue , strlen(saltValue) , 64000, 16 , keybuffer );
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


/* Cleanup handles  */


void cleanup()
{
    gcry_cipher_close(handle);
    gcry_md_close(digestHandle);
}

/*

String operations - 

Accepting password
Generating salt

*/

char * requestPassword()
{
  char *pwd = (char *)malloc(1024);
  printf("\nPassword : \t");
  scanf("%s",pwd);
  return pwd;
}

//this method can be modified to return a truly random salt
char * fetchSaltForPassword()
{
  return "hamzakarachi";
}

