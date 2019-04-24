# GandCrab String Decryptor

Ida C script for string decryption.

Tested with GandCrab v 5.1 (DLL) and GandCrab v 5.2 (exe) and 5.3 (exe)

Testing samples SHA265:
  - 6aa3f17e5f62b715908b5cb3ea462bfa6cecfd3f4d70078eabd418291a5a7b83
  - 017b236bf38a1cf9a52fc0bdee2d5f23f038b00f9811c8a58b8b66b1c756b8d6
  - 1791e9d01451f953e74249019654609cd33c2ab66e97f2ed7a609e99f9ce8320
  - d01fd7176d48d8210fe85923ff383d87dab7d2e2b37e9da58c7e075a1aae153c

## How it works

This script will try to identify the string decrypt function, which should be the heavily used function and it should be short.
String decryption function takes one argument and extracts from it the key, length of encrypted data and encrypted data itself. Encryption is RC4, as we can see below:

![String decryption function](gandcrab_decrypt_string_function.png)

![RC4 decryption](gandcrab_RC4_decrypt_function.png)

Then, this script finds the calls to the string decryption and reconstructs its argument from "mov" instructions which manipulate with the local variables (see picture below). After the extraction of the parameters for RC4 it is possible to decrypt string and perform check if it is ASCII or Unicode string. Finaly, this script makes the comments with decrypted values:

![RC4 decryption](gandcrab_decrypted_strings.png)

![RC4 decryption](gandcrab_script_output.png)
