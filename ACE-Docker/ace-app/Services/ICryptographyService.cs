using ACEWebService.Entities;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ACEWebService.Services
{
    public interface ICryptographyService
    {
        string Encrypt(string clearText);
        string Decrypt(string cipherText);
    }

    public class AESCryptographyService : ICryptographyService
    {
        IConfigurationRoot _configuration;

        public AESCryptographyService(IConfigurationRoot configuration)
        {
            _configuration = configuration;
        }

        private static int _iterations = 2;
        private static int _keySize = 256;

        private static string _salt = "8c4f1fcf93cdd79b"; // Random
        private static string _vector = "5748b84005dc40e9"; // Random

        public string Encrypt(string clearText)
        {
            byte[] vectorBytes = Encoding.ASCII.GetBytes(_vector);
            byte[] saltBytes = Encoding.ASCII.GetBytes(_salt);

            Rfc2898DeriveBytes _passwordBytes = new Rfc2898DeriveBytes(_configuration["EncryptionPassphrase"], saltBytes, _iterations);
            byte[] keyBytes = _passwordBytes.GetBytes(_keySize / 8);

            using (var aesAlg = Aes.Create())
            {
                using (var encryptor = aesAlg.CreateEncryptor(keyBytes, vectorBytes))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (var swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(clearText);
                            }

                            var decryptedContent = msEncrypt.ToArray();

                            return Convert.ToBase64String(decryptedContent);
                        }
                    }
                }
            }
        }

        public string Decrypt(string cipherText)
        {
            byte[] vectorBytes = Encoding.ASCII.GetBytes(_vector);
            byte[] saltBytes = Encoding.ASCII.GetBytes(_salt);
            byte[] valueBytes = Convert.FromBase64String(cipherText);

            byte[] decrypted;
            int decryptedByteCount = 0;

            using (Aes aesAlg = Aes.Create())
            {
                Rfc2898DeriveBytes _passwordBytes = new Rfc2898DeriveBytes(_configuration["EncryptionPassphrase"], saltBytes, _iterations);
                byte[] keyBytes = _passwordBytes.GetBytes(_keySize / 8);

                aesAlg.Mode = CipherMode.CBC;

                using (var decryptor = aesAlg.CreateDecryptor(keyBytes, vectorBytes))
                {
                    using (MemoryStream msDecrypt = new MemoryStream(valueBytes))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            decrypted = new byte[valueBytes.Length];
                            decryptedByteCount = csDecrypt.Read(decrypted, 0, decrypted.Length);
                        }
                    }
                }
            }

            return Encoding.UTF8.GetString(decrypted, 0, decryptedByteCount);
        }

        /*
        public string Encrypt(string clearText)
        {
            return Encrypt(clearText, _configuration["EncryptionPassphrase"]);
        }

        public string Decrypt(string cipherText)
        {
            return Decrypt(cipherText, _configuration["EncryptionPassphrase"]);
        }

        #region Settings

        private static int _iterations = 2;
        private static int _keySize = 256;

        private static string _hash = "SHA1";
        private static string _salt = "8c4f1fcf93cdd79b"; // Random
        private static string _vector = "5748b84005dc40e9"; // Random

        #endregion Settings

        private static string Encrypt(string value, string password)
        {
            return Encrypt<AesManaged>(value, password);
        }
        private static string Encrypt<T>(string value, string password)
                where T : SymmetricAlgorithm, new()
        {
            byte[] vectorBytes = Encoding.ASCII.GetBytes(_vector);
            byte[] saltBytes = Encoding.ASCII.GetBytes(_salt);
            byte[] valueBytes = Encoding.UTF8.GetBytes(value);

            byte[] encrypted;
            using (T cipher = new T())
            {
                PasswordDeriveBytes _passwordBytes =
                    new PasswordDeriveBytes(password, saltBytes, _hash, _iterations);
                byte[] keyBytes = _passwordBytes.GetBytes(_keySize / 8);

                cipher.Mode = CipherMode.CBC;

                using (ICryptoTransform encryptor = cipher.CreateEncryptor(keyBytes, vectorBytes))
                {
                    using (MemoryStream to = new MemoryStream())
                    {
                        using (CryptoStream writer = new CryptoStream(to, encryptor, CryptoStreamMode.Write))
                        {
                            writer.Write(valueBytes, 0, valueBytes.Length);
                            writer.FlushFinalBlock();
                            encrypted = to.ToArray();
                        }
                    }
                }
                cipher.Clear();
            }
            return Convert.ToBase64String(encrypted);
        }

        private static string Decrypt(string value, string password)
        {
            return Decrypt<AesManaged>(value, password);
        }
        private static string Decrypt<T>(string value, string password) where T : SymmetricAlgorithm, new()
        {
            byte[] vectorBytes = Encoding.ASCII.GetBytes(_vector);
            byte[] saltBytes = Encoding.ASCII.GetBytes(_salt);
            byte[] valueBytes = Convert.FromBase64String(value);

            byte[] decrypted;
            int decryptedByteCount = 0;

            using (T cipher = new T())
            {
                PasswordDeriveBytes _passwordBytes = new PasswordDeriveBytes(password, saltBytes, _hash, _iterations);
                byte[] keyBytes = _passwordBytes.GetBytes(_keySize / 8);

                cipher.Mode = CipherMode.CBC;

                try
                {
                    using (ICryptoTransform decryptor = cipher.CreateDecryptor(keyBytes, vectorBytes))
                    {
                        using (MemoryStream from = new MemoryStream(valueBytes))
                        {
                            using (CryptoStream reader = new CryptoStream(from, decryptor, CryptoStreamMode.Read))
                            {
                                decrypted = new byte[valueBytes.Length];
                                decryptedByteCount = reader.Read(decrypted, 0, decrypted.Length);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    return String.Empty;
                }

                cipher.Clear();
            }
            return Encoding.UTF8.GetString(decrypted, 0, decryptedByteCount);
        }
        */
    }
}