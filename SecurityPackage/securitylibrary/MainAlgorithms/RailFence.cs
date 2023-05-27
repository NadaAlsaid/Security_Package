using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int max = 0;
            int j = 0;
            cipherText = cipherText.ToLower();
            for (int i = 1; i <= cipherText.Length / 2; i++)
            {
                for (; j < plainText.Length; j++)
                {
                    if (cipherText[i] == plainText[j])
                    {
                        max++;
                        break;
                    }
                }
                if (max == 3)
                    break;

            }
            if (Encrypt(plainText, j / 4 + 1) == cipherText)
                return j / 4 + 1;

            return 2;
            // anathor solution 
            /* string cipher = "";
            for (int key = 2; key < 100; key++)
            {

                cipher = Encrypt(plainText, key);
                if (cipher == cipherText)
                {
                    return key;
                }

            }
            return 0;*/
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            int col = 0, index = 0;
            char[,] plain = new char[key, (cipherText.Length / key) + 1];
            int size;
            if (cipherText.Length % key == 0)
                size = (cipherText.Length / key);
            else
                size = (cipherText.Length / key) + 1;
            for (int depth = 0; depth < key; depth++)
            {
                for (col = 0; col < size; col++)
                {
                    if (index < cipherText.Length)
                        plain[depth, col] = cipherText[index];
                    index++;
                }
            }
            for (col = 0; col < size; col++)
            {
                for (int depth = 0; depth < key; depth++)
                {
                    if (plain[depth, col] != '\0')
                        plainText += plain[depth, col];
                }
            }
            //throw new NotImplementedException();
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";
            char[,] cipher = new char[key, (plainText.Length / key) + 1];
            int col = 0, index = 0;
            while (index < plainText.Length)
            {
                for (int depth = 0; depth < key; depth++)
                {
                    if (index < plainText.Length)
                        cipher[depth, col] = plainText[index];
                    index++;
                }
                col++;
            }
            for (int depth = 0; depth < key; depth++)
            {
                for (col = 0; col < (plainText.Length / key) + 1; col++)
                {
                    if (cipher[depth, col] != '\0')
                        cipherText += cipher[depth, col];
                }
            }
            //throw new NotImplementedException();
            return cipherText;
        }
    }
}
