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
            Console.WriteLine("Введите хеш-таблица размером 20 символов: ");
            string TextIn = Console.ReadLine();
            HashValue = Convert.FromBase64String(Convert.ToBase64String(Encoding.UTF8.GetBytes(TextIn)));
            //Хеш таблица состоит из 20 бит, через консоль вводимые
            string text = Encoding.UTF8.GetString(HashValue);
            Console.WriteLine(text);
            // Подписываем хеш-таблицу с помощью закрытого ключа
            byte[] SignedHashValue = DSASignHash(HashValue, privateKeyInfo, "SHA1");
            text = Encoding.UTF8.GetString(SignedHashValue);

            Console.WriteLine(text);
            // Сверяем подписанную неподписанную Хеш-таблицу с помощью открытого ключа
            bool verified = DSAVerifyHash(HashValue, SignedHashValue, publicKeyInfo, "SHA1");

            if (verified)
            {
                Console.WriteLine("Значение хеш-таблицы совпало");
            }
            else
            {
                Console.WriteLine("Значение хеш-таблицы не совпало");
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
            // Создаем новыый экземпляр класса
            using (DSACryptoServiceProvider DSA = new DSACryptoServiceProvider())
            {
                // Импортируем ключи, в данном случае закрытый ключ
                DSA.ImportParameters(DSAKeyInfo);

                // Создаем объект класса DSASignatureFormatter и передаем ему DSACryptoServiceProvider закрытый ключ
                DSASignatureFormatter DSAFormatter = new DSASignatureFormatter(DSA);

                // Устанавливаем алгоритм шифрования
                DSAFormatter.SetHashAlgorithm(HashAlg);

                // Создаем подпись для хеш-таблицы и возвращаем ее значение
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
            // Создаем новый экземпляр класса DSACryptoServiceProvider.
            using (DSACryptoServiceProvider DSA = new DSACryptoServiceProvider())
            {
                // Импортируем ключи
                DSA.ImportParameters(DSAKeyInfo);

                //Создаем объект класса DSASignatureFormatter и передаем ему DSACryptoServiceProvider закрытый ключ
                DSASignatureDeformatter DSADeformatter = new DSASignatureDeformatter(DSA);

                // Устанавливаем алгоритм шифрования
                DSADeformatter.SetHashAlgorithm(HashAlg);

                // Сверяем подписи и возвращаем результат
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
