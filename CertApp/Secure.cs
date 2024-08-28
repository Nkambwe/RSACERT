using System.Text;
using System.Security.Cryptography;

namespace CertApp {
    public class Secure {
        
        public static string GenerateSignature(string payload, RSA privateKey) {
            byte[] data = Encoding.UTF8.GetBytes(payload);
            string? config = CryptoConfig.MapNameToOID("SHA256");

            if (!string.IsNullOrEmpty(config)) {
                byte[] signature = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return Convert.ToBase64String(signature);
            }

            throw new InvalidOperationException("Unable to map algorithm name.");
        }

        public static bool VerifySignature(string payload, string signature, RSA publicKey) {
            byte[] data = Encoding.UTF8.GetBytes(payload);
            byte[] sig = Convert.FromBase64String(signature);
            return publicKey.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

    }
}
