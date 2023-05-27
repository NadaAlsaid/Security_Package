using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            string key = "";
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {

                int c = (cipherText[i] - plainText[i]);
                if (c >= 0)
                    key += (char)('a' + (c));
                else
                    key += (char)('z' - Math.Abs(c) + 1);
            }
            string k = string.Join("", key.Distinct()), newKey = "";
            for (int i = 0; i < key.Length; i++)
            {
                if (i > k.Length && key[i] == k[0])
                {
                    break;
                }
                newKey += key[i];
            }
            return newKey;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string plainText = "";
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {

                int c = (cipherText[i] - key[i % key.Length]);
                if (c >= 0)
                    plainText += (char)('a' + (c));
                else
                    plainText += (char)('z' - Math.Abs(c) + 1);
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {

                char c = (char)(key[i % key.Length] + Math.Abs(plainText[i] - 'a'));
                if (c <= 'z')
                    cipherText += c;
                else
                    cipherText += (char)('a' + (c - 'z' - 1));
            }
            return cipherText;
        }
    }
}