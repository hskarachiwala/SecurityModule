# SecurityModule

Name - Hamza Shabbir Karachiwala [61961544]

Source Files - 

gatorenc.c => Performs the encryption
gatordec.c => Performs the decryption
commonassignmentfiles => Code common to both files, prevent duplication

Overview - 

Code Layout - 

Comments - 

PBKDF2 - 
The decisions needed to be made are -
Which sub algorithm (hash function) should be used - SHA512, it is currently recommended
Salt value - This is the extra input required by PBKDF2. It provides the added protection against dictionary attacks and provides uniqueness to the hashes of passwords. It must be any random value, with no real restrictions as it is public anyway.
 
How does your program deal with it?

Effort - Please refer to the excel sheet for a detailed account 


