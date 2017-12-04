using Microsoft.AspNetCore.DataProtection;

namespace ACEWebService.Services
{
    public interface ICryptographyService
    {
        string Encrypt(string clearText);
        string Decrypt(string cipherText);
    }

    public class AESCryptographyService : ICryptographyService
    {
        private readonly IDataProtector _protector;

        public AESCryptographyService(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector(GetType().FullName);
        }

        public string Encrypt(string plaintext)
        {
            return _protector.Protect(plaintext);
        }

        public string Decrypt(string encryptedText)
        {
            return _protector.Unprotect(encryptedText);
        }
    }
}