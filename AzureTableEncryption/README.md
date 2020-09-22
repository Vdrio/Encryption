# Vdrio Azure TableEntity Encryption
> Simplify encryption on your Azure table entities with just attributes!

## Table of contents
* [General info](#general-info)
* [Setup](#setup)
* [Code Examples](#code-examples)
* [Status](#status)
* [Contact](#contact)

## General info
I use AES Encryption in most of my projects and this makes it much easier to encrypt my Azure Table Entities.


## Setup
Once you have this installed and referenced in your project you need to referece Vdrio.Security.Encryption.AzureTable and then have your TableEntity class inherit from EncryptedTableEntity instead of TableEntity. Then, add the [EncryptedProperty] attribute on the properties you wish to be encrypted and set the [EncryptionKey(a,b,c)] attribute on the class to set the key. See example implementation below.

## Code Examples

Encryption Examples:
```csharp

    [EncryptionKey(100, 20, 68)]
    public class EncryptedObject:EncryptedTableEntity
    {

        public string PublicInfo { get; set; }

        [EncryptedProperty]
        public string SecretInfo { get; set; }

        [EncryptedProperty]
        public List<EncryptedObject> EncryptedObjects { get; set; }

    }

    //The values will be stored as encrypted when you check your Azure Table Storage, but will be decrypted when you retrieve them. 
```



To-do list:
* Do more testing before official v1.0 release

## Status
Project is: _in progress_

## Contact
Created by [@Vdrio](lucasdglass@outlook.com) - feel free to contact me!
