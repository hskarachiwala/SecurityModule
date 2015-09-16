# SecurityModule

Name - Hamza Shabbir Karachiwala [61961544]

Source Files - 

gatorenc.c => Performs the encryption
gatordec.c => Performs the decryption
commonassignmentfiles => Code common to both files, prevent duplication

Overview - 


Code Layout - 



PBKDF2 - 
The decisions needed to be made are -
1) Which sub algorithm (hash function) should be used - SHA512, it is currently recommended.
2) Salt value - This is the extra input required by PBKDF2. It provides the added protection against dictionary attacks and provides uniqueness to the hashes of passwords. It must be any random value, with no real restrictions as it is public anyway.
3) The number of rounds - 64000 is again the minimum requirement by standards but I am doing just 100.
 
How does your program deal with it?
I am writing the salt value to the beginning of the encrypted file. The salt value is currently hardcoded but can be randomly generated. The decryption reads it from the file and utilizes it.

Effort - Please refer to the excel sheet for a detailed account 

