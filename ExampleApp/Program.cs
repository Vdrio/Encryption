using Microsoft.Azure.Cosmos.Table;
using Microsoft.Azure.Cosmos.Table.Queryable;
using System;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using Vdrio.Security.Encryption.AzureTable;

namespace ExampleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            UploadData();
            Console.ReadLine();
        }

        public static async void GetData()
        {
            var storageAccount = new CloudStorageAccount(new StorageCredentials("[storage account name]", "[storage account key]"), true);
            var tableClient = storageAccount.CreateCloudTableClient();
            var cryptoTable = tableClient.GetTableReference("TestEncryption");
            await cryptoTable.CreateIfNotExistsAsync();
            var query = (from entity in cryptoTable.CreateQuery<EncryptedObject>()
                         select entity);
            var queryResult = query.AsTableQuery();
            TableContinuationToken token = null;
            TableQuerySegment<EncryptedObject> tableEntities = await cryptoTable.ExecuteQuerySegmentedAsync(queryResult, token);
            foreach(EncryptedObject o in tableEntities.Results)
            {
                Console.WriteLine(o.SecretInfo);
                foreach(EncryptedObject e in o.EncryptedObjects??new System.Collections.Generic.List<EncryptedObject>())
                {
                    Console.WriteLine(e.SecretInfo);
                }
            }
            
        }

        public static async void UploadData()
        {
            try
            {
                var storageAccount = new CloudStorageAccount(new StorageCredentials("[storage account name]", "[storage account key]"), true);
                var tableClient = storageAccount.CreateCloudTableClient();
                var cryptoTable = tableClient.GetTableReference("TestEncryption");
                await cryptoTable.CreateIfNotExistsAsync();
                TableOperation operation = TableOperation.InsertOrReplace(new EncryptedObject() { PublicInfo = "Hello", SecretInfo = "Goodbye",EncryptedObjects = new System.Collections.Generic.List<EncryptedObject>() { new EncryptedObject { RowKey = Guid.NewGuid().ToString(), PartitionKey = "Tests", PublicInfo = "Hello again", SecretInfo = "Goodbye again" } }, RowKey = Guid.NewGuid().ToString(), PartitionKey = "Tests" });
                await cryptoTable.ExecuteAsync(operation);
                await Task.Delay(1000);
                GetData();
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
