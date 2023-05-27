using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {


        public string Encrypt(string plainText, int key)
        {//throw new NotImplementedException
            string ciphertext = "";


            for (int i = 0; i < plainText.Length; i++)
            {

                if (char.IsUpper(plainText[i]))
                    ciphertext += (char)(((int)plainText[i] + key - 65) % 26 + 65);


                else
                    ciphertext += (char)((int)(plainText[i] + key - 97) % 26 + 97);
            }

            return ciphertext;
        }

        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();
            string plaintext = "";


            for (int i = 0; i < cipherText.Length; i++)
            {

                if (char.IsUpper(cipherText[i]))
                    plaintext += (char)(((int)cipherText[i] - key + 65) % 26 + 65);


                else
                    plaintext += (char)((int)(cipherText[i] - key - 97) % 26 - 97);
            }

            return plaintext;
        }

        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;

            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            Dictionary<char, int> dic = new Dictionary<char, int>();
            for (int i = 0; i < 26; i++)
            {
                dic.Add((char)('A' + i), i);
            }
            key = dic[cipherText[0]] - dic[plainText[0]];

            if (key < 0)
            {
                key = key + 26;
            }
            return key;
        }

    }
}
