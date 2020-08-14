using System;
using System.Collections.Generic;
using System.Text;

namespace Vdrio.Security.Encryption.Examples
{
    public static class AESEncryptionExamples
    {
        static string secretInfo = "mySuperSecretPassword";

        static string encryptedSecretInfo = null;

        static string key = null;

        static string iv = null;

        public static string EncryptMySecret()
        {
            iv = AESEncryptor.CreateInitializor();
            key = AESEncryptor.CreateNewKey();
            encryptedSecretInfo = AESEncryptor.EncryptTo64String(secretInfo, iv);
            return encryptedSecretInfo;
        }

        public static string DecryptMySecret()
        {
            AESEncryptor.SetKey(key);
            string decryptedInfo = AESEncryptor.Decrypt(encryptedSecretInfo, iv);
            return decryptedInfo;
        }

    }
}
