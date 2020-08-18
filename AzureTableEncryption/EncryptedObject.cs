using System;
using System.Collections.Generic;
using System.Text;

namespace Vdrio.Security.Encryption.AzureTable
{
#if DEBUG
    public class EncryptedObject:EncryptedTableEntity
    {

        public string PublicInfo { get; set; }

        [EncryptedProperty]
        public string SecretInfo { get; set; }

        [EncryptedProperty]
        public List<EncryptedObject> EncryptedObjects { get; set; }


    }
#endif
}
