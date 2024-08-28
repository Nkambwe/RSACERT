using System.Security.Cryptography;
using static System.Console;

namespace CertApp {
    public static partial class Program {
        public static void Main(string[] args) {

            // Generate the self-signed certificate
            string apiKey ="eu41s&cer7";
            string certPath= Path.Combine("C:\\Users\\Mark.Nkambwe\\Documents\\eunis", "enu_cert.pfx");
            string privPath= Path.Combine("C:\\Users\\Mark.Nkambwe\\Documents\\eunis\\keys1", "eunis_prv.xml");
            string pubPath = Path.Combine("C:\\Users\\Mark.Nkambwe\\Documents\\eunis\\keys2", "eunis_pub.xml");

            // Save the certificate to a file
            Generators.GenerateAndSaveKeys(certPath, apiKey, privPath, pubPath);

            // Load the keys
            RSA privateKey = Generators.LoadPrivateKey(privPath);
            RSA publicKey = Generators.LoadPublicKey(pubPath);

            //..test
            string payload = "This is the payload.";

            // Sign the payload using the private key
            string signature = Secure.GenerateSignature(payload, privateKey);
            WriteLine($"Signature: {signature}");

            // Verify the payload using the public key
            bool isValid = Secure.VerifySignature(payload, signature, publicKey);
            WriteLine($"Is the signature valid? {isValid}");
            
            ReadKey();
        }
    }
}

