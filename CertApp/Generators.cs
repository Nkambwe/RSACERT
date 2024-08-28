using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertApp {
    public class Generators {

        /// <summary>
        /// Generate certificate to share using private key
        /// </summary>
        /// <param name="certName">Certificate subject name</param>
        /// <param name="apiKey">Private Key</param>
        /// <returns>Generated certificate</returns>
        public static X509Certificate2 GenerateSelfSignedCertificate(string certName, string apiKey) {
            using (var rsa = RSA.Create(2048)) {
                var request = new CertificateRequest(
                    new X500DistinguishedName($"CN={certName}"),
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                // Add extensions if needed, e.g., Basic Constraints, Key Usage, etc.
                request.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, true));

                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                        true));

                request.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

                // Generate the self-signed certificate
                var certificate = request.CreateSelfSigned(
                    DateTimeOffset.Now,
                    DateTimeOffset.Now.AddYears(5));

                // Export the certificate with the private key, protected by the password
                return new X509Certificate2(
                    certificate.Export(X509ContentType.Pfx, apiKey),
                    apiKey,
                    X509KeyStorageFlags.MachineKeySet |
                    X509KeyStorageFlags.PersistKeySet |
                    X509KeyStorageFlags.Exportable);
            }
        }

        public static void SaveCertificateToFile(X509Certificate2 certificate, string filePath, string apiKey) {
            byte[] certData = certificate.Export(X509ContentType.Pfx, apiKey);
            File.WriteAllBytes(filePath, certData);
        }

        public static void GenerateAndSaveKeys(string certPath, string apiKey, string privateKeyPath, string publicKeyPath) {
            // Generate the self-signed certificate
            X509Certificate2 certificate = GenerateSelfSignedCertificate(certPath, apiKey);

            RSA? rsa = certificate.GetRSAPrivateKey();
            if (rsa != null) {
                using (rsa) {
                    if (rsa != null) {
                        string privateKeyXml = rsa.ToXmlString(true);
                        File.WriteAllText(privateKeyPath, privateKeyXml);

                        string publicKeyXml = rsa.ToXmlString(false);
                        File.WriteAllText(publicKeyPath, publicKeyXml);
                    }
                }
                SaveCertificateToFile(certificate, certPath, apiKey);
            } else {
                Console.WriteLine("Certificate not generated");
            }
            
        }

        public static RSA LoadPrivateKey(string privateKeyPath) {
            string privateKeyXml = File.ReadAllText(privateKeyPath);
            var rsa = RSA.Create();
            rsa.FromXmlString(privateKeyXml);
            return rsa;
        }

        public static RSA LoadPublicKey(string publicKeyPath) {
            string publicKeyXml = File.ReadAllText(publicKeyPath);
            var rsa = RSA.Create();
            rsa.FromXmlString(publicKeyXml);
            return rsa;
        }
    }
}
