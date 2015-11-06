using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.IO;
using System.Security;
using System.Threading.Tasks;



namespace DSA
{
    class Program
    {
        
    public static void Main()
    {
        try
        {
        
            DSAParameters privateKeyInfo;
            DSAParameters publicKeyInfo;

            //Создаем пару ключей(открытый и закрытый)
            using (DSACryptoServiceProvider DSA = new DSACryptoServiceProvider())
            {
                privateKeyInfo = DSA.ExportParameters(true);
                publicKeyInfo = DSA.ExportParameters(false);
            }
            // Хеш таблица
            byte[] HashValue = new byte[20]; 
            string TextIn = Console.ReadLine();
            HashValue = Convert.FromBase64String(Convert.ToBase64String(Encoding.UTF8.GetBytes(TextIn)));
            //Хеш таблица состоит из 20 бит, через консоль вводимые
            string text = Encoding.UTF8.GetString(HashValue);
            Console.WriteLine(text);
            // The value to hold the signed value.
            byte[] SignedHashValue = DSASignHash(HashValue, privateKeyInfo, "SHA1");
            text = Encoding.UTF8.GetString(SignedHashValue);

            Console.WriteLine(text);
            // Verify the hash and display the results.
            bool verified = DSAVerifyHash(HashValue, SignedHashValue, publicKeyInfo, "SHA1");

            if (verified)
            {
                Console.WriteLine("The hash value was verified.");
            }
            else
            {
                Console.WriteLine("The hash value was not verified.");
            }
        }
        catch (ArgumentNullException e)
        {
            Console.WriteLine(e.Message);
        }
        Console.ReadKey();
    }

      
//-------------------------------------------------------------------------
        // Шифруем закрытым ключем Хеш-таблицу
    public static byte[] DSASignHash(byte[] HashToSign, DSAParameters DSAKeyInfo,
        string HashAlg)
    {
        byte[] sig = null;

        try
        {
            // Create a new instance of DSACryptoServiceProvider.
            using (DSACryptoServiceProvider DSA = new DSACryptoServiceProvider())
            {
                // Import the key information.
                DSA.ImportParameters(DSAKeyInfo);

                // Create an DSASignatureFormatter object and pass it the
                // DSACryptoServiceProvider to transfer the private key.
                DSASignatureFormatter DSAFormatter = new DSASignatureFormatter(DSA);

                // Set the hash algorithm to the passed value.
                DSAFormatter.SetHashAlgorithm(HashAlg);

                // Create a signature for HashValue and return it.
                sig = DSAFormatter.CreateSignature(HashToSign);
            }
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);
        }

        return sig;
    }
//-------------------------------------------------------------------
    public static bool DSAVerifyHash(byte[] HashValue, byte[] SignedHashValue,
        DSAParameters DSAKeyInfo, string HashAlg)
    {
        bool verified = false;

        try
        {
            // Create a new instance of DSACryptoServiceProvider.
            using (DSACryptoServiceProvider DSA = new DSACryptoServiceProvider())
            {
                // Import the key information.
                DSA.ImportParameters(DSAKeyInfo);

                // Create an DSASignatureDeformatter object and pass it the
                // DSACryptoServiceProvider to transfer the private key.
                DSASignatureDeformatter DSADeformatter = new DSASignatureDeformatter(DSA);

                // Set the hash algorithm to the passed value.
                DSADeformatter.SetHashAlgorithm(HashAlg);

                // Verify signature and return the result.
                verified = DSADeformatter.VerifySignature(HashValue, SignedHashValue);
            }
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);
        }

        return verified;
    }
}



    }
