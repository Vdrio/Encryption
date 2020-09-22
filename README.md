# Vdrio .NET Standard AES Encryption
> Simplify your 256-bit AES Encryption for all your .NET projects

## Table of contents
* [General info](#general-info)
* [Setup](#setup)
* [Code Examples](#code-examples)
* [Status](#status)
* [Contact](#contact)

## General info
I use AES Encryption in most of my projects and this makes it much easier to get going.


## Setup
Once you have this installed and referenced in your project you just need to referece Vdrio.Security.Encryption in the files you wish to use it in. The previous version utilized a static AESEncryptor class. This static class still works and still contains some useful functions (see examples), but it is now recommended to use the EncryptionManager class to perform encryption and decryption. See examples for usage.

## Code Examples

Encryption Examples:
```csharp

    //the secret info we are going to encrypt
    string secretInfo = "mySuperSecretPassword";

    string encryptedSecretInfo = null;

    //this is your 64-bit key string
    string myKeyString = AESEncryptor.CreateNewKey();

    using (var manager = new EncryptionManager(myKeyString))
    {
        //This is your initializor, or public key
        string iv = AESEncryptor.CreateInitializor();
                 
        //This is how you encrypt with your specified key and iv
        encryptedSecretInfo = manager.Encrypt(secretInfo, iv);
    }


    //you can also encrypt with private keys of int a, b and c
    using (var manager = new EncryptionManager(100,50,10))
    {
        //This is your initializor, or public key
        string iv = AESEncryptor.CreateInitializor();

        //This is your second public key, used with a, b, and c to compute the private key
        long ticks = DateTime.Now.Ticks;

        //This is how you encrypt with your specified key and iv
        encryptedSecretInfo = manager.Encrypt(secretInfo, iv, ticks);
    }

    //Make sure you save your public and private keys so you can decrypt the data!

```



Decryption Example:
```csharp
    //When trying to decrypt your data, you will need your public key (iv) and optionally a second public key (time in ticks)
    public static string DecryptMySecret(string encryptedData, string iv, long ticks)
    {
        //this is your 64-bit key string
        string myKeyString = AESEncryptor.CreateNewKey();

        string decryptedSecretInfo = null;

        //create EncryptionManager with your key string
        using (var manager = new EncryptionManager(myKeyString))
        {
            //This is how you decrypt with your keyString (private key) and iv (public key)
            decryptedSecretInfo = manager.Decrypt(encryptedData, iv);
        }


        //you can also decrypt with private keys of int a, b and c
        using (var manager = new EncryptionManager(100, 50, 10))
        {
            //This is how you decrypt with your specified keys, iv and ticks
            decryptedSecretInfo = manager.Decrypt(encryptedData, iv, ticks);
        }

        return decryptedSecretInfo;
    }
```



To-do list:
* Do more testing before official v1.0 release

## Status
Project is: _in progress_

## Contact
Created by [@Vdrio](lucasdglass@outlook.com) - feel free to contact me!
