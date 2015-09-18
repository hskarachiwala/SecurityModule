# SecurityModule

Name - Hamza Shabbir Karachiwala [61961544]

I] Source Files - 

gatorenc.c => Performs the encryption
gatordec.c => Performs the decryption
commonassignmentfiles => Code common to both files, prevent duplication


II] Code Layout - 

=> gatordec is currently fixed to run on 127.0.0.1 only, i.e gatordec <port> will run on 127.0.0.1:<port>

The code is divided over 3 files - 

1) gatorenc.c - reads from a file,performs the encryption, calculates the hash and attaches the hash to the output file along with encypted data.

2) gatordec.c - extracts the hash, recomputes a new hash, verifies both and then decrypts the contents of the output file to a new file.

3) commomassignmentfiles.h - contains some code comon to both files, and other general string functions along with function definitions. Helps to reduce code duplication and keeps the other files relatively clean.

Flow of gatorenc.c on invocation- 

1) We first check the mode of operation whether it is -l or -d. We perform certain error checks accordingly for command format, file availability, etc.

2) We then accept a password from the user and begin the encryption process.

3) We initialize the handler, generate the password using pbkdf2 and set the output as the key for encryption. During this process we use a random salt and write it to the output file as well.

4) We then read the file contents character by character into 128 byte size buffer. We pass this buffer to the encryption function and write the results to the output file. We write the data after leaving 128 bytes from the start. This space is left for the HMAC.

5) After the data is written, we read it back into a buffer and calculate the HMAC. For this we use the same key as in the encryption. The HMAC is written from 32 bytes onwards in the file.

6) If needed we then transmit this file using a stream socket preceded by the file name itself

Flow of gatordec.c on invocation - 

1) Based on the mode, we will either create sockets and listen on the parameter <port> or we will read the encrypted file. The IP is currently fixed to 127.0.0.1. 

2) We then open the encrpted file and read the salt. We then extract the the hash attached to the message. Following this we recompute the hash for the file contents. We compare both these hash values and verify that the data is intact.

3) We then follow the same initialization procedure as with encryption. This is why there is a common header file for this code.

4) We perform decryption andd write to the file again. We lose the .uf extension during decryption which was appended after encryption.


III] PBKDF2 - 
The decisions needed to be made are -

1) Which sub algorithm (hash function) should be used - SHA256, it is currently recommended.

2) Salt value - This is the extra input required by PBKDF2. It provides the added protection against dictionary attacks and provides uniqueness to the hashes of passwords. It must be any random value, with no real restrictions as it is public anyway. I have a function that returns a hard coded salt value, this function can be modified to return a random string. This salt value is written at the start of the encrypted file from where it is read for the decryption process.

3) The number of rounds - 64000 is again the minimum requirement by standards but I am doing just 100.
 
IV] Effort - Please refer to the excel sheet for a detailed account of effort put into the assignment.

