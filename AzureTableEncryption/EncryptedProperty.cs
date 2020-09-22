using System;
using System.Collections.Generic;
using System.Text;

namespace Vdrio.Security.Encryption.AzureTable
{
    [AttributeUsage(AttributeTargets.Property)]
    public class EncryptedProperty : Attribute
    {
        public string EncryptedValue { get; set; }

        public EncryptedProperty()
        {

        }
    }

    [AttributeUsage(AttributeTargets.Class)]
    public class EncryptionKey : Attribute
    {
        public bool IsDefaultValue { get; private set; } = true;
        public byte[] Key { get; set; }

        public int A { get; private set; } = 24;
        public int B { get; private set; } = 8;
        public int C { get; private set; } = 3;

        public bool isSingleKey { get; private set; } = false;

        public EncryptionKey(string keyString)
        {
            Key = Convert.FromBase64String(keyString);
            isSingleKey = true;
        }
        public EncryptionKey(byte[] key)
        {
            Key = key;
            isSingleKey = true;
        }
        public EncryptionKey(int a, int b, int c)
        {
            A = a;
            B = b;
            C = c;
            if (A!= 24 || B!= 8 || C!= 3)
            {
                IsDefaultValue = false;
            }
            isSingleKey = false;
        }
    }
}
