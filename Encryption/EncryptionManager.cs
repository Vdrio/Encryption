using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Vdrio.Security.Encryption
{
    public class EncryptionManager : IDisposable
    {
        public AesManaged AESManager { get; private set; }

        public int A { get; private set; } = 24;
        public int B { get; private set; } = 8;
        public int C { get; private set; } = 3;

        private int  BaseEvenIntKey{get;set;}
        private int  BaseOddIntKey{get;set;}

        private bool singleKeyManager = false;
        public EncryptionManager(string privateKey)
        {
            try
            {
                AESManager = new AesManaged();
                AESManager.Key = Convert.FromBase64String(privateKey);
                singleKeyManager = true;
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }
        
        public EncryptionManager(byte[] privateKey)
        {
            try
            {
                AESManager = new AesManaged();
                AESManager.Key = privateKey;
                singleKeyManager = true;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public EncryptionManager(int a, int b, int c)
        {
            A = a;
            B = b;
            C = c;
            BaseOddIntKey = (new Random(7 * A)).Next(1000000000) + (new Random(11 * B)).Next(1000000000) + (new Random(13 * C)).Next(1000000000);
            BaseEvenIntKey = (new Random(7 * C)).Next(1000000000) + (new Random(11 * B)).Next(1000000000) + (new Random(13 * A)).Next(1000000000);
            singleKeyManager = false;
        }

        /// <summary>
        /// Encrypts plainText value with IV and ticks and returns encrypted string
        /// </summary>
        public string Encrypt(string plainText, string iv, long ticks)
        {
            if (singleKeyManager)
            {
                throw new InvalidOperationException("This instance of EncryptionManager was not expecting parameter of ticks. Use constructor with a, b and c instead.");
            }
            if (AESManager == null)
            {
                AESManager = new AesManaged();
            }
            Random random;
            if (ticks % 2 == 0)
            {
                random = new Random(BaseEvenIntKey + (int)(ticks % 1000000000));
            }
            else
            {
                random = new Random(BaseOddIntKey + (int)(ticks % 1000000000));
            }
            byte[] bytes = new byte[32];
            random.NextBytes(bytes);
            AESManager.Key = bytes;
            var encryptor = AESManager.CreateEncryptor(AESManager.Key, Convert.FromBase64String(iv));
            byte[] encrypted;

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                    encrypted = ms.ToArray();
                }
            }
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts plainBytes value with IV and ticks and returns encrypted bytes
        /// </summary>
        public byte[] Encrypt(byte[] plainBytes, byte[] iv, long ticks)
        {
            try
            {
                if (singleKeyManager)
                {
                    throw new InvalidOperationException("This instance of EncryptionManager was not expecting parameter of ticks. Use constructor with a, b and c instead.");
                }
                if (AESManager == null)
                {
                    AESManager = new AesManaged();
                }
                Random random;
                if (ticks % 2 == 0)
                {
                    random = new Random(BaseEvenIntKey + (int)(ticks % 1000000000));
                }
                else
                {
                    random = new Random(BaseOddIntKey + (int)(ticks % 1000000000));
                }
                byte[] bytes = new byte[32];
                random.NextBytes(bytes);
                AESManager.Key = bytes;
                var encryptor = AESManager.CreateEncryptor(AESManager.Key, iv);
                byte[] encrypted;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
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
                throw ex;
            }
        }

        /// <summary>
        /// Encrypts plainBytes value with IV and returns encrypted bytes
        /// </summary>
        public byte[] Encrypt(byte[] plainBytes, byte[] iv)
        {
            try
            {
                if (!singleKeyManager)
                {
                    throw new InvalidOperationException("This instance of EncryptionManager was expecting parameter of ticks");
                }
                if (AESManager == null)
                {
                    AESManager = new AesManaged();
                }
                var encryptor = AESManager.CreateEncryptor(AESManager.Key, iv);
                byte[] encrypted;
                //byte[] data = Encoding.UTF8.GetBytes(plainText);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
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
                throw ex;
            }
        }


        /// <summary>
        /// Encrypts plainText value with IV and returns encrypted string
        /// </summary>
        public string Encrypt(string plainText, string iv)
        {
            try
            {
                if (!singleKeyManager)
                {
                    throw new InvalidOperationException("This instance of EncryptionManager was expecting parameter of ticks");
                }
                if (AESManager == null)
                {
                    AESManager = new AesManaged();
                }
                var encryptor = AESManager.CreateEncryptor(AESManager.Key, Convert.FromBase64String(iv));
                byte[] encrypted;
                //byte[] data = Encoding.UTF8.GetBytes(plainText);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                        encrypted = ms.ToArray();
                    }
                }
                return Convert.ToBase64String(encrypted);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                throw ex;
            }
        }

        /// <summary>
        /// Decrypts cipherText value with IV and returns decrypted bytes
        /// </summary>
        public byte[] DecryptToBytes(string cipherText, string iv)
        {
            try
            {
                return Convert.FromBase64String(Decrypt(Convert.FromBase64String(cipherText), Convert.FromBase64String(iv)));
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                throw ex;
            }
        }

        /// <summary>
        /// Decrypts cipherText value with IV and ticks and returns decrypted bytes
        /// </summary>
        public byte[] DecryptToBytes(string cipherText, string iv, long ticks)
        {
            try
            {
                return Convert.FromBase64String(Decrypt(Convert.FromBase64String(cipherText), Convert.FromBase64String(iv), ticks));
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                throw ex;
            }
        }

        /// <summary>
        /// Decrypts cipherText value with IV and ticks and returns decrypted string
        /// </summary>
        public string Decrypt(string cipherText, string iv, long ticks)
        {
            try
            {
                return Decrypt(Convert.FromBase64String(cipherText), Convert.FromBase64String(iv), ticks);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                throw ex;
            }
        }

        /// <summary>
        /// Decrypts cipherText value with IV and returns decrypted string
        /// </summary>
        public string Decrypt(string cipherText, string iv)
        {
            try
            {
                return Decrypt(Convert.FromBase64String(cipherText), Convert.FromBase64String(iv));
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                throw ex;
            }
        }

        /// <summary>
        /// Decrypts cipherText value with IV and text and returns decrypted string
        /// </summary>
        public string Decrypt(byte[] cipherText, byte[] iv, long ticks)
        {
            try
            {
                string plaintext = null;
                // Create AesManaged
                if (singleKeyManager)
                {
                    throw new InvalidOperationException("This instance of EncryptionManager was not expecting parameter of ticks. Use constructor with a, b and c instead.");
                }
                if (AESManager == null)
                {
                    AESManager = new AesManaged();
                }
                Random random;
                if (ticks % 2 == 0)
                {
                    random = new Random(BaseEvenIntKey + (int)(ticks % 1000000000));
                }
                else
                {
                    random = new Random(BaseOddIntKey + (int)(ticks % 1000000000));
                }
                byte[] bytes = new byte[32];
                random.NextBytes(bytes);
                AESManager.Key = bytes;

                // Create a decryptor    
                ICryptoTransform decryptor = AESManager.CreateDecryptor(AESManager.Key, iv);
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
                throw ex;
            }
        }


        /// <summary>
        /// Decrypts cipherText value with IV and returns decrypted string
        /// </summary>
        public string Decrypt(byte[] cipherText, byte[] iv)
        {
            try
            {
                string plaintext = null;
                // Create AesManaged    
                if (!singleKeyManager)
                {
                    throw new InvalidOperationException("This instance of EncryptionManager was expecting parameter of ticks.");
                }
                if (AESManager == null)
                {
                    AESManager = new AesManaged();
                }
                // Create a decryptor    
                ICryptoTransform decryptor = AESManager.CreateDecryptor(AESManager.Key, iv);
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
                throw ex;
            }
        }

        public void Dispose()
        {
            AESManager?.Dispose();
        }
    }
}
