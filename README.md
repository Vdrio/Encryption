# Vdrio AES Encryption
> Simplify your 256-bit AES Encryption with one static class and easy-to-use methods

## Table of contents
* [General info](#general-info)
* [Setup](#setup)
* [Code Examples](#code-examples)
* [Status](#status)
* [Contact](#contact)

## General info
I use AES Encryption in most of my projects and this makes it much easier to get going.


## Setup
Once you have this installed and referenced in your project you just need to referece Vdrio.Security.Encryption in the files you wish to use it in. 

## Code Examples
Initialization Example:
```csharp
using Vdrio.Security.Encryption;

//Initialize with random 256-bit encryption key
AESEncryptor.Initialize();

//Gets the private key so you can save it for decryption later
string key = AESEncryptor.GetCurrentKey();

//Initialize with a known private key in the format of Base64 string
AESEncryptor.Initialize(keyString);

//Note: initialization will happen automatically when any method is called
```

Encryption Example:
```csharp
//Secret string to Encrypt
string secretInfo = "mySuperSecretPassword";

//Create Initialization Vector (aka Public Key)
iv = AESEncryptor.CreateInitializor();

//Create new public key and keep reference
key = AESEncryptor.CreateNewKey();

//Encrypt secretInfo to Base 64 string. Encrypt can return Base 64 string or byte[] and has overloads to have byte[] or string inputs
encryptedSecretInfo = AESEncryptor.EncryptTo64String(secretInfo, iv);
```  

Values in the above example:
key = "bvXeawD4xTVI9SmxjSXtBm8X/7hrdb0qdmQHXJO4cRc="  

iv = "sVhK0HBOyrRTcRALzbxecg=="  

encryptedSecretInfo = "rQN2NmmzqtL9uHx3p9Ajch28EOtYkmrjIbKp871kvuE="


Decryption Example:
```csharp
//Encrypted string to Decrypt from previous example
encryptedSecretInfo = AESEncryptor.EncryptTo64String(secretInfo, iv);

//Set key to previous used key (only necessary when switching Private Keys)
AESEncryptor.SetKey(key);

//Decrypt info using the iv (public key) from previous example
string decryptedSecretInfo = AESEncryptor.Decrypt(encryptedSecretInfo, iv);
```
Values in the above example:  

encryptedSecretInfo = "rQN2NmmzqtL9uHx3p9Ajch28EOtYkmrjIbKp871kvuE="  

decryptedSecretInfo = "mySuperSecretPassword"  



To-do list:
* Ability to store keys in encrypted file at specified location
* Non-static implementation to make it easier to use multiple private keys

## Status
Project is: _in progress_

## Contact
Created by [@Vdrio](lucasdglass@outlook.com) - feel free to contact me!
