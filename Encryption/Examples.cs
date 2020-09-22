using System;
using System.Collections.Generic;
using System.Text;

namespace Vdrio.Security.Encryption.Examples
{
    public static class AESEncryptionExamples
    {
        static string secretInfo = "mySuperSecretPassword";

        static string encryptedSecretInfo = null;


        public static string EncryptMySecret()
        {
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
                string iv = manager.CreateInitializor();

                //This is your second public key, used with a, b, and c to compute the private key
                long ticks = DateTime.Now.Ticks;

                //This is how you encrypt with your specified key and iv
                encryptedSecretInfo = manager.Encrypt(secretInfo, iv, ticks);
            }

            return encryptedSecretInfo;
        }

        //When trying to decrypt your data, you will need your public key (iv) and optionally a second public key (time in ticks)
        public static string DecryptMySecret(string encryptedData, string iv, long ticks)
        {
            //this is your 64-bit key string
            string myKeyString = AESEncryptor.CreateNewKey();

            string decryptedSecretInfo = null;

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

    }
}
