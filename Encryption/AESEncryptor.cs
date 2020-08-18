using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Vdrio.Security.Encryption
{
    public static class AESEncryptor
    {
        static bool Initialized = false;
        static AesManaged EncryptionManager;
        static ICryptoTransform Encryptor;
        static readonly string keyString = "YzvNjApj2/p8rPt6nmrQXK4XXpjZGKIUHAgRwLmTvec=";
        static RandomNumberGenerator NumberGenerator;
        static string KeyString { get; set; }// = keyString;

        /// <summary>
        /// Initialize must be called before encryption can be performed
        /// </summary>
        public static void Initialize()
        {
            EncryptionManager = new AesManaged();
            try
            {
                if (File.Exists(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption", "aesencryptionkey.txt")))
                {
                    byte[] key = File.ReadAllBytes(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption", "aesencryptionkey.txt"));
                        byte[] bytes = new byte[32];
                    Random random = new Random(5649954 + 6247112);

                    random.NextBytes(bytes);
                    EncryptionManager.Key = bytes;
                    byte[] iv = new byte[16];
                    random.NextBytes(iv);
                    Initialized = true;
                    KeyString = Decrypt(key, iv);
                    EncryptionManager.Key = Convert.FromBase64String(KeyString);
                }
                else if (string.IsNullOrWhiteSpace(KeyString))
                {
                    Random random = new Random(5649954 + 6247112);
                    byte[] bytes = new byte[32];
                    random.NextBytes(bytes);
                    EncryptionManager.Key = bytes;
                    byte[] iv = new byte[16];
                    random.NextBytes(iv);
                    byte[] userKey = new byte[32];
                    random.NextBytes(userKey);
                    KeyString = Convert.ToBase64String(userKey);
                    Initialized = true;
                    if (!Directory.Exists(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption")))
                    {
                        Directory.CreateDirectory(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption"));
                    }
                    byte[] encryptedBytes = Encrypt(Convert.ToBase64String(userKey), iv);
                    System.IO.File.WriteAllBytes(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption", "aesencryptionkey.txt"), encryptedBytes);
                    EncryptionManager.Key = userKey;
                }
                else
                {
                    EncryptionManager.Key = Convert.FromBase64String(KeyString);
                }
            }
            catch(Exception ex)
            {
                Random random = new Random(5649954 + 6247112);
                byte[] bytes = new byte[32];
                random.NextBytes(bytes);
                EncryptionManager.Key = bytes;
                byte[] iv = new byte[16];
                random.NextBytes(iv);
                byte[] userKey = new byte[32];
                random.NextBytes(userKey);
                KeyString = Convert.ToBase64String(userKey);
                Initialized = true;
                if (!Directory.Exists(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption")))
                {
                    Directory.CreateDirectory(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption"));
                }
                byte[] encryptedBytes = Encrypt(Convert.ToBase64String(userKey), iv);
                System.IO.File.WriteAllBytes(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption", "aesencryptionkey.txt"), encryptedBytes);
                EncryptionManager.Key = userKey;
                Debug.WriteLine(ex);
            }

            NumberGenerator = new RNGCryptoServiceProvider();
            Initialized = true;
        }

        /// <summary>
        /// Initialize(keyString) can be manually called to initialize with specified Base 64 String. Returns false if failed, usually due to a key issue
        /// </summary>
        public static bool Initialize(string keyString)
        {
            try
            {
                EncryptionManager = new AesManaged();
                EncryptionManager.Key = Convert.FromBase64String(keyString);
                NumberGenerator = new RNGCryptoServiceProvider();
                Initialized = true;
                return true;
            }
            catch(Exception ex)
            {
                Debug.WriteLine(ex);
                return false;
            }
        }


        /// <summary>
        /// Creates, applies and returns new Base 64 string
        /// </summary>
        public static string CreateNewKey()
        {
            if (!Initialized)
            {
                Initialize();
            }
            EncryptionManager.GenerateKey();
            KeyString = Convert.ToBase64String(EncryptionManager.Key);
            byte[] bytes = new byte[32];
            Random random = new Random(5649954 + 6247112);
            random.NextBytes(bytes);
            EncryptionManager.Key = bytes;
            byte[] iv = new byte[16];
            random.NextBytes(iv);
            if (!Directory.Exists(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption")))
            {
                Directory.CreateDirectory(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption"));
            }
            byte[] encryptedBytes = Encrypt(KeyString, iv);
            System.IO.File.WriteAllBytes(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption", "aesencryptionkey.txt"), encryptedBytes);
            EncryptionManager.Key = Convert.FromBase64String(KeyString);
            return KeyString;
        }

        /// <summary>
        /// Returns current encryption key in Base 64 string
        /// </summary>
        public static string GetCurrentKey()
        {
            if (!Initialized)
            {
                Initialize();
            }
            KeyString = Convert.ToBase64String(EncryptionManager.Key);
            return KeyString;
        }

        /// <summary>
        /// Sets current encryption key from Base 64 string
        /// </summary>
        public static string SetKey(string keyString)
        {
            if (!Initialized)
            {
                Initialize();
            }
            try
            {
                Random random = new Random(5649954 + 6247112);
                byte[] bytes = new byte[32];
                random.NextBytes(bytes);
                EncryptionManager.Key = bytes;
                byte[] iv = new byte[16];
                random.NextBytes(iv);
                KeyString = keyString;
                if (!Directory.Exists(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption")))
                {
                    Directory.CreateDirectory(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption"));
                }
                byte[] encryptedBytes = Encrypt(keyString, iv);
                System.IO.File.WriteAllBytes(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Encryption", "aesencryptionkey.txt"), encryptedBytes);
                EncryptionManager.Key = Convert.FromBase64String(keyString);
                return KeyString;
            }
            catch(Exception ex)
            {
                Debug.WriteLine(ex);
                return null;
            }
        }

        /// <summary>
        /// Encrypts plainText value with IV and returns encrypted string
        /// </summary>
        public static string EncryptTo64String(string plainText, byte[] iv)
        {
            byte[] encrypted = Encrypt(plainText, iv);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts plainText value with IV and returns encrypted string
        /// </summary>
        public static string EncryptTo64String(string plainText, string iv)
        {
            byte[] encrypted = Encrypt(plainText, Convert.FromBase64String(iv));
            string encryptedString = Convert.ToBase64String(encrypted);
            return encryptedString;
        }

        /// <summary>
        /// Encrypts plainBytes value with IV and returns encrypted bytes
        /// </summary>
        public static byte[] Encrypt(byte[] plainBytes, byte[] iv)
        {
            try
            {
                if (!Initialized)
                {
                    Initialize();
                }
                Encryptor = EncryptionManager.CreateEncryptor(EncryptionManager.Key, iv);
                byte[] encrypted;
                //byte[] data = Encoding.UTF8.GetBytes(plainText);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, Encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainBytes);
                        }
                        encrypted = ms.ToArray();
                    }
                }
                return encrypted;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                return null;
            }
        }

        /// <summary>
        /// Encrypts plainText value with IV and returns encrypted bytes
        /// </summary>
        public static byte[] Encrypt(string plainText, byte[] iv)
        {
            try
            {
                if (!Initialized)
                {
                    Initialize();
                }
                Encryptor = EncryptionManager.CreateEncryptor(EncryptionManager.Key, iv);
                byte[] encrypted;
                //byte[] data = Encoding.UTF8.GetBytes(plainText);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, Encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                        encrypted = ms.ToArray();
                    }
                }
                return encrypted;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                return null;
            }
        }

        /// <summary>
        /// Decrypts cipherText value with IV and returns decrypted string
        /// </summary>
        public static string Decrypt(byte[] cipherText, byte[] iv)
        {
            if (!Initialized)
            {
                Initialize();
            }
            try
            {
                string plaintext = null;
                // Create AesManaged    

                // Create a decryptor    
                ICryptoTransform decryptor = EncryptionManager.CreateDecryptor(EncryptionManager.Key, iv);
                // Create the streams used for decryption.    
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Create crypto stream    
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Read crypto stream    
                        using (StreamReader reader = new StreamReader(cs))
                        {
                            plaintext = reader.ReadToEnd();
                        }

                    }
                }

                return plaintext;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                return null;
            }
        }

        /// <summary>
        /// Decrypts cipherText value with IV and returns decrypted string
        /// </summary>
        public static string Decrypt(string cipherText, string iv)
        {
            if (!Initialized)
            {
                Initialize();
            }
            try
            {
                string plaintext = null;
                // Create AesManaged    

                // Create a decryptor    
                ICryptoTransform decryptor = EncryptionManager.CreateDecryptor(EncryptionManager.Key, Convert.FromBase64String(iv));
                // Create the streams used for decryption.    
                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    // Create crypto stream    
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Read crypto stream    
                        using (StreamReader reader = new StreamReader(cs))
                        {
                            plaintext = reader.ReadToEnd();
                        }

                    }
                }

                return plaintext;
            }
            catch(Exception ex)
            {
                Debug.WriteLine(ex);
                return null;
            }
        }

        /// <summary>
        /// Creates a new Initialization Vector (IV) and returns it as Base 64 string
        /// </summary>
        public static string CreateInitializor()
        {
            if (!Initialized)
            {
                Initialize();
            }
            EncryptionManager.GenerateIV();
            return Convert.ToBase64String(EncryptionManager.IV);
        }

        /// <summary>
        /// Creates a new Initialization Vector (IV) and returns it as bytes
        /// </summary>
        public static byte[] CreateInitializorBytes()
        {
            if (!Initialized)
            {
                Initialize();
            }
            EncryptionManager.GenerateIV();
            return EncryptionManager.IV;
        }
    }
}
