# RSAPoisoner
Tool for standard attacks on the RSA cryptosystem

## Running
Open up the terminal on the directory containing RSAPoisoner.sage and run the following command:
```
sage RSAPoisoner.sage
```

## Instructions
When asked to enter data, enter the integer form of the data. Except for the conversions, all other options strictly take numbers as input.

## Features
1. **RSA Encrypt** -> Performs unpadded RSA encryption
2. **RSA Decrypt (d known)** -> Decrypts RSA when private exponent d is known
3. **RSA Decrypt (factors known)** -> Decrypts RSA when factors of the prime modulus are known
4. **Common Modulus Attack (External)** -> Uncovers plaintext given external attacker details in a common modulus situation
5. **Common Modulus Attack (Internal)** -> Uncovers private exponent d given internal attacker details in a common modulus situation
6. **Small Public Exponent Attack** -> Uncovers plaintext when the public exponent is too small
7. **Hastad's Broadcast Attack** -> Uncovers plaintext broadcasted e times using Hastad's broadcast attack
8. **Wiener's Attack** -> Attempts to uncover private exponent d using Wiener's attack
9. **Fermat's Factorisation** -> Attemps factorisation by Fermat's factorisation method
10. **Twin Primes Factorisation** -> Attempts factorisaton of a product of twin primes
11. **Extract Modulus (e known)** -> Extracts the unknown prime modulus given appropriate plaintext-ciphertext pairs when public exponent e is known
12. **Extract Modulus (e unknown)** -> Extracts the unknown prime modulus given appropriate plaintext-ciphertext pairs when public exponent e is unknown
13. **String To Long** -> Converts an ASCII string to its integer representation
14. **Long To String** -> Converts an integer to its ASCII representation
15. **Hex To Long** -> Converts a hexadecimal to its integer value
16. **Long To Hex** -> Converts an integer into its hexadecimal value
17. **String To Hex** -> Converts an ASCII string to its hexadecimal value
18. **Hex To String** -> Converts a hexadecimal value to its ASCII string
19. **Exit** -> Exits the tool

## Warning
The current version of the tool performs absolutely NO error-handling. It assumes that the user enters appropriate inputs and does not try to crash the program. I plan on implementing error-handling in the future.
