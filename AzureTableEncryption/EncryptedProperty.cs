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
}
