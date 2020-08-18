using Microsoft.Azure.Cosmos.Table;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Vdrio.Security.Encryption;

namespace Vdrio.Security.Encryption.AzureTable
{
    public class EncryptedTableEntity : ITableEntity
    {
        public string PartitionKey { get; set; }
        public string RowKey { get; set; }
        public DateTimeOffset Timestamp { get; set; }
        public string ETag { get; set; }

        public string IV { get
            {
                if (string.IsNullOrEmpty(iv))
                {
                    iv = AESEncryptor.CreateInitializor();
                }
                return iv;
            } set { iv = value; } }
        private string iv;

        public void ReadEntity(IDictionary<string, EntityProperty> properties, OperationContext operationContext)
        {
#if RT
            IEnumerable<PropertyInfo> myProperties = entity.GetType().GetRuntimeProperties();
#else
            IEnumerable<PropertyInfo> myProperties = this.GetType().GetProperties();
#endif
            PropertyInfo iv = myProperties.First(x => x.Name == "IV");
            iv.SetValue(this, properties["IV"]?.StringValue);
            foreach (PropertyInfo property in myProperties)
            {
                // reserved properties
                if (property.Name == "PartitionKey" ||
                    property.Name == "RowKey" ||
                    property.Name == "Timestamp" ||
                    property.Name == "ETag")
                {
                    continue;
                }
                // Enforce public getter / setter
#if RT
                if (property.SetMethod == null || !property.SetMethod.IsPublic || property.GetMethod == null || !property.GetMethod.IsPublic)
#else

                if (property.GetSetMethod() == null || !property.GetSetMethod().IsPublic || property.GetGetMethod() == null || !property.GetGetMethod().IsPublic)
#endif
                {
                    continue;
                }

                // only proceed with properties that have a corresponding entry in the dictionary
                if (!properties.ContainsKey(property.Name))
                {
                    continue;
                }

                EntityProperty entityProperty = properties[property.Name];



                if (IsPropertyNull(entityProperty))
                {
                    property.SetValue(this, null, null);
                }
                else if (property.GetCustomAttribute(typeof(EncryptedProperty)) is EncryptedProperty encryptedAttribute)
                {
                    object propValue = null;
                    try
                    {
                        if (entityProperty.PropertyType == EdmType.String)
                        {
                            propValue = JsonConvert.DeserializeObject(AESEncryptor.Decrypt(entityProperty.StringValue, IV), property.PropertyType);
                        }

                    }catch(Exception ex)
                    {
                        Console.Write(ex);
                    }

                    if (propValue != null)
                    {
                        property.SetValue(this, propValue, null);
                    }
                    
                    else
                    {
                        switch (entityProperty.PropertyType)
                        {
                            case EdmType.String:
                                if (property.PropertyType != typeof(string) && property.PropertyType != typeof(String))
                                {
                                    continue;
                                }
                                var propertyValue = AESEncryptor.Decrypt(entityProperty.StringValue, IV);
                                property.SetValue(this, propertyValue, null);
                                break;
                            case EdmType.Binary:
                                if (property.PropertyType != typeof(byte[]))
                                {
                                    continue;
                                }

                                var binaryValue = JsonConvert.DeserializeObject<byte[]>(AESEncryptor.Decrypt(entityProperty.StringValue, IV));
                                property.SetValue(this, binaryValue, null);
                                break;
                            case EdmType.Boolean:
                                if (property.PropertyType != typeof(bool) && property.PropertyType != typeof(Boolean) && property.PropertyType != typeof(Boolean?) && property.PropertyType != typeof(bool?))
                                {
                                    continue;
                                }

                                property.SetValue(this, entityProperty.BooleanValue, null);
                                break;
                            case EdmType.DateTime:
                                if (property.PropertyType == typeof(DateTimeOffset))
                                {
                                    var dateValue = JsonConvert.DeserializeObject<DateTimeOffset>(AESEncryptor.Decrypt(entityProperty.StringValue, IV));
                                    property.SetValue(this, dateValue.UtcDateTime, null);
                                }
                                else if (property.PropertyType == typeof(DateTimeOffset))
                                {
                                    var dateValue = JsonConvert.DeserializeObject<DateTime>(AESEncryptor.Decrypt(entityProperty.StringValue, IV));
                                    property.SetValue(this, dateValue.ToUniversalTime(), null);
                                }


                                break;
                            case EdmType.Double:
                                if (property.PropertyType != typeof(double) && property.PropertyType != typeof(Double) && property.PropertyType != typeof(Double?) && property.PropertyType != typeof(double?))
                                {
                                    continue;
                                }

                                var doubleValue = JsonConvert.DeserializeObject<double>(AESEncryptor.Decrypt(entityProperty.StringValue, IV));
                                property.SetValue(this, doubleValue, null);
                                break;
                            case EdmType.Guid:
                                if (property.PropertyType != typeof(Guid) && property.PropertyType != typeof(Guid?))
                                {
                                    continue;
                                }

                                var guidValue = JsonConvert.DeserializeObject<Guid>(AESEncryptor.Decrypt(entityProperty.StringValue, IV));
                                property.SetValue(this, guidValue, null);
                                break;
                            case EdmType.Int32:
                                if (property.PropertyType != typeof(int) && property.PropertyType != typeof(Int32) && property.PropertyType != typeof(Int32?) && property.PropertyType != typeof(int?))
                                {
                                    continue;
                                }

                                var intValue = JsonConvert.DeserializeObject<int>(AESEncryptor.Decrypt(entityProperty.StringValue, IV));
                                property.SetValue(this, intValue, null);
                                break;
                            case EdmType.Int64:
                                if (property.PropertyType != typeof(long) && property.PropertyType != typeof(Int64) && property.PropertyType != typeof(long?) && property.PropertyType != typeof(Int64?))
                                {
                                    continue;
                                }
                                var intValue2 = JsonConvert.DeserializeObject<int>(AESEncryptor.Decrypt(entityProperty.StringValue, IV));
                                property.SetValue(this, intValue2, null);
                                break;

                        }
                    }
                }
                else
                {
                    switch (entityProperty.PropertyType)
                    {
                        case EdmType.String:
                            if (property.PropertyType != typeof(string) && property.PropertyType != typeof(String))
                            {
                                continue;
                            }

                            property.SetValue(this, entityProperty.StringValue, null);
                            break;
                        case EdmType.Binary:
                            if (property.PropertyType != typeof(byte[]))
                            {
                                continue;
                            }

                            property.SetValue(this, entityProperty.BinaryValue, null);
                            break;
                        case EdmType.Boolean:
                            if (property.PropertyType != typeof(bool) && property.PropertyType != typeof(Boolean) && property.PropertyType != typeof(Boolean?) && property.PropertyType != typeof(bool?))
                            {
                                continue;
                            }

                            property.SetValue(this, entityProperty.BooleanValue, null);
                            break;
                        case EdmType.DateTime:
                            if (property.PropertyType == typeof(DateTime))
                            {
                                property.SetValue(this, entityProperty.DateTimeOffsetValue.Value.UtcDateTime, null);
                            }
                            else if (property.PropertyType == typeof(DateTime?))
                            {
                                property.SetValue(this, entityProperty.DateTimeOffsetValue.HasValue ? entityProperty.DateTimeOffsetValue.Value.UtcDateTime : (DateTime?)null, null);
                            }
                            else if (property.PropertyType == typeof(DateTimeOffset))
                            {
                                property.SetValue(this, entityProperty.DateTimeOffsetValue.Value, null);
                            }
                            else if (property.PropertyType == typeof(DateTimeOffset?))
                            {
                                property.SetValue(this, entityProperty.DateTimeOffsetValue, null);
                            }

                            break;
                        case EdmType.Double:
                            if (property.PropertyType != typeof(double) && property.PropertyType != typeof(Double) && property.PropertyType != typeof(Double?) && property.PropertyType != typeof(double?))
                            {
                                continue;
                            }

                            property.SetValue(this, entityProperty.DoubleValue, null);
                            break;
                        case EdmType.Guid:
                            if (property.PropertyType != typeof(Guid) && property.PropertyType != typeof(Guid?))
                            {
                                continue;
                            }

                            property.SetValue(this, entityProperty.GuidValue, null);
                            break;
                        case EdmType.Int32:
                            if (property.PropertyType != typeof(int) && property.PropertyType != typeof(Int32) && property.PropertyType != typeof(Int32?) && property.PropertyType != typeof(int?))
                            {
                                continue;
                            }

                            property.SetValue(this, entityProperty.Int32Value, null);
                            break;
                        case EdmType.Int64:
                            if (property.PropertyType != typeof(long) && property.PropertyType != typeof(Int64) && property.PropertyType != typeof(long?) && property.PropertyType != typeof(Int64?))
                            {
                                continue;
                            }

                            property.SetValue(this, entityProperty.Int64Value, null);
                            break;
                    }
                }
            }
        }

        public IDictionary<string, EntityProperty> WriteEntity(OperationContext operationContext)
        {
            Dictionary<string, EntityProperty> retVals = new Dictionary<string, EntityProperty>();

#if RT
            IEnumerable<PropertyInfo> objectProperties = entity.GetType().GetRuntimeProperties();
#else
            IEnumerable<PropertyInfo> objectProperties = this.GetType().GetProperties();
#endif

            foreach (PropertyInfo property in objectProperties)
            {
                // reserved properties
                if (property.Name == "PartitionKey" ||
                    property.Name == "RowKey" ||
                    property.Name == "Timestamp" ||
                    property.Name == "ETag")
                {
                    continue;
                }

                // Enforce public getter / setter
#if RT
                if (property.SetMethod == null || !property.SetMethod.IsPublic || property.GetMethod == null || !property.GetMethod.IsPublic)
#else
                if (property.GetSetMethod() == null || !property.GetSetMethod().IsPublic || property.GetGetMethod() == null || !property.GetGetMethod().IsPublic)
#endif
                {
                    continue;
                }

                EntityProperty newProperty = null;
                if (property.GetCustomAttribute(typeof(EncryptedProperty)) != null)
                {
                    newProperty = CreateEntityPropertyFromObject(Convert.ToBase64String(AESEncryptor.Encrypt(JsonConvert.SerializeObject(property.GetValue(this, null)), Convert.FromBase64String(IV))), false);
                }
                else
                {
                    newProperty = CreateEntityPropertyFromObject(property.GetValue(this, null), false);
                }

                // property will be null if unknown type
                if (newProperty != null)
                {
                    retVals.Add(property.Name, newProperty);
                }
            }

            return retVals;
        }

        private EntityProperty CreateEntityPropertyFromObject(object value, bool allowUnknownTypes)
        {
            if (value is string)
            {
                return new EntityProperty((string)value);
            }
            else if (value is byte[])
            {
                return new EntityProperty((byte[])value);
            }
            else if (value is bool)
            {
                return new EntityProperty((bool)value);
            }
            else if (value is bool?)
            {
                return new EntityProperty((bool?)value);
            }
            else if (value is DateTime)
            {
                return new EntityProperty((DateTime)value);
            }
            else if (value is DateTime?)
            {
                return new EntityProperty((DateTime?)value);
            }
            else if (value is DateTimeOffset)
            {
                return new EntityProperty((DateTimeOffset)value);
            }
            else if (value is DateTimeOffset?)
            {
                return new EntityProperty((DateTimeOffset?)value);
            }
            else if (value is double)
            {
                return new EntityProperty((double)value);
            }
            else if (value is double?)
            {
                return new EntityProperty((double?)value);
            }
            else if (value is Guid?)
            {
                return new EntityProperty((Guid?)value);
            }
            else if (value is Guid)
            {
                return new EntityProperty((Guid)value);
            }
            else if (value is int)
            {
                return new EntityProperty((int)value);
            }
            else if (value is int?)
            {
                return new EntityProperty((int?)value);
            }
            else if (value is long)
            {
                return new EntityProperty((long)value);
            }
            else if (value is long?)
            {
                return new EntityProperty((long?)value);
            }
            else if (value == null)
            {
                return new EntityProperty((string)null);
            }
            else if (allowUnknownTypes)
            {
                return new EntityProperty(value.ToString());
            }
            else
            {
                return null;
            }
        }

        private static bool IsPropertyNull(EntityProperty prop)
        {
            switch (prop.PropertyType)
            {
                case EdmType.Binary:
                    return prop.BinaryValue == null;
                case EdmType.Boolean:
                    return !prop.BooleanValue.HasValue;
                case EdmType.DateTime:
                    return !prop.DateTimeOffsetValue.HasValue;
                case EdmType.Double:
                    return !prop.DoubleValue.HasValue;
                case EdmType.Guid:
                    return !prop.GuidValue.HasValue;
                case EdmType.Int32:
                    return !prop.Int32Value.HasValue;
                case EdmType.Int64:
                    return !prop.Int64Value.HasValue;
                case EdmType.String:
                    return prop.StringValue == null;
                default:
                    throw new InvalidOperationException("Unknown type!");
            }
        }
    }
}
