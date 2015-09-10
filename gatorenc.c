#include<stdio.h>
#include<gcrypt.h>
#include<string.h>


char * requestPassword();

int main(int argc,char *argv[])
{
  int gcryptInitStatus;
  char *filename,*password = NULL;

  char buffer[1024];
  char output[1024];

  FILE *srcFile,*destFile;

  gcry_cipher_hd_t handle;
  gcry_error_t err = 0;
  
  if( !InitializeGcrypt() )
    return 0;

  if (argc<2)                   //no filename given
  {
    printf("Missing file name to encrypt\n");
    return 0;
  }


  filename = argv[1];
  srcFile = fopen(filename,"r");      //open file
  
  if(srcFile == NULL)           //file not found
  {
    printf("File not found");
    return 0;
  }
  else
  {
    destFile = fopen(strcat(filename,".uf"),"w");     
    password = requestPassword();   //get password 16 characters
    
    do
    {
      fgets(buffer,1024,srcFile);   //pick from file


      err = gcry_cipher_open (&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC,0);    //create handle
  
      if (err)
      {
        printf ("Failure: %s%s\n",gcry_strsource (err),gcry_strerror (err));
        printf ("Failure: %s%s\n",gcry_strsource (err),gcry_strerror (err));
      }

      err = gcry_cipher_setkey (handle, password,128);          //set key to encrypt
      if (err)
      {
        printf ("Failure: %s%s\n",gcry_strsource (err),gcry_strerror (err));
        printf ("Failure: %s%s\n",gcry_strsource (err),gcry_strerror (err));
      }

      err =  gcry_cipher_encrypt (handle,output,1024,buffer,1024);    //encrypt
      if (err)
      {
        printf ("Failure: %s%s\n",gcry_strsource (err),gcry_strerror (err));
        printf ("Failure: %s%s\n",gcry_strsource (err),gcry_strerror (err));
      }
  
      printf(" out :%s ||| plain text %s\n",output, buffer);

      fputs(output,destFile);    //write to encrypted file
    }while( !feof(srcFile) );

    printf("%s",buffer);

    fclose(destFile);   //close both files
    fclose(srcFile);
  }
  
    
}

char * requestPassword()
{
  int length;
  
  char *pwd = (char *)malloc(16);

  do
  {
    printf("Enter your pasword - 16 characters");
    scanf("%s",pwd);
  }while(strlen(pwd) > 16);

  return pwd;
}

int InitializeGcrypt()
{
  if (!gcry_check_version (GCRYPT_VERSION))               //version check
  {
    fputs ("libgcrypt version mismatch\n", stderr);
    return 0;
  }
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);           // suspend warnings
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);         // allocate secure memory
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);            // allow warnings
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);    // signal that we are done

  return 1;
}









