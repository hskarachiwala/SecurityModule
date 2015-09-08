#include<stdio.h>
#include<gcrypt.h>
#include<string.h>

int main(int argc,char *argv[])
{
  int gcryptInitStatus;
  char *filename;
  char buffer[1024];
  FILE *srcFile,*destFile;
  
  if( !InitializeGcrypt() )
    return 0;

  if (argc<2)
  {
    printf("Missing file name to encrypt\n");
    return 0;
  }

  filename = argv[1];
  srcFile = fopen(filename,"r");
  if(srcFile!=NULL)
  {
    do
    {
      fgets(buffer,1024,srcFile);
    }while( !feof(srcFile) );

    printf("%s",buffer);
    fclose(srcFile);
  }
  else
  {
    printf("File not found");
  }

  if(buffer[0]!='\n')
  {
    destFile = fopen(strcat(filename,".uf"),"w");
    fputs(buffer,destFile);
    fclose(destFile);
  }
    
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









