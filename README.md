# Identity2John

A little tool to format Password hashs generated by Microsoft Identity Core for use John The Ripper to crack it.

```
$ ./Identity2John -h
Identity2John 1.0.1

Convert a Base64 password hash (PBKDF2-HMAC-SHA1/PBKDF2-HMAC-SHA256/PBKDF2-HMAC-SHA512) generated by Microsft.Identity (V2 or V3) to JohnTheRipper input format.
If no option, read standard input.

Usage: Identity2John [options]

Options:
  --version                Show version information.
  -s|--hash <HASH>         [user:]base64Hash
  -S|--hashes <HASH_FILE>  A file with a [user:]base64Hash by line
  -?|-h|--help             Show help information.
```

## Example
```
└─$ ./Identity2John -s AQAAAAEAABOIAAAAENskwqzCBxN6KrN3sJ8tvWzsylAVMC9foN1zSe4kVS5q/JPIZ3wXvibqVJXSuzRrNQ== > hash.txt

└─$ cat hash.txt          
$pbkdf2-sha256$5000$2yTCrMIHE3oqs3ewny29bA$7MpQFTAvX6Ddc0nuJFUuavyTyGd8F74m6lSV0rs0azU

└─$ john --wordlist=wordlist hash.txt                                                            
Using default input encoding: UTF-8
Loaded 1 password hash (PBKDF2-HMAC-SHA256 [PBKDF2-SHA256 128/128 AVX 4x])
No password hashes left to crack (see FAQ)
                                                                                                                                                                                       └─$ john --show hash.txt
?:Test

1 password hash cracked, 0 left
                                 
```
