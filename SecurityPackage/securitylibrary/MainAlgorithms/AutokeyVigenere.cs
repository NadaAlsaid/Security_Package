using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        char[,] alphabetMatrix = new char[26, 26];

        public AutokeyVigenere()
        {
            char start = 'A';
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if ((start + j) > 'Z')
                    {
                        alphabetMatrix[i, j] = (char)((start + j) - 'Z' + 'A' - 1);
                    }
                    else
                    {
                        alphabetMatrix[i, j] = (char)(start + j);
                    }
                }
                start++;
            }
        }
        public char[,] Fillmatrix()
        {
            char[] alpha = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
            int index;
            char[,] matrix = new char[26, 26];
            int real = 0;
            for (int i = 0; i < alpha.Length; i++)
            {
                index = i;
                for (int J = 0; J < alpha.Length - i; J++)
                {
                    matrix[i, J] = alpha[index];
                    index++;
                    real = J;
                }
                if (i != 0)
                {
                    index = 0;
                    for (int x = 0; x < i; x++)
                    {
                        matrix[i, real + 1] = alpha[index];
                        index++;
                        real++;
                    }
                }
            }
            return matrix;
        }
        char[] alpha = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            char[,] matrix = Fillmatrix();
            string key = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < alpha.Length; j++)
                {
                    if (plainText[i] == alpha[j])
                    {
                        for (int x = 0; x < 26; x++)
                        {
                            if (matrix[x, j] == cipherText[i])
                            {
                                key += alpha[x];
                                break;
                            }
                        }
                    }
                }
            }
            for (int i = 3; i < key.Length; i++)
            {
                if (key[i] == plainText[0] && key[i + 1] == plainText[1] && key[i + 2] == plainText[2])
                {
                    int cou = key.Length - i;
                    key = key.Remove(i, cou);

                }
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            char[,] shiftletters = genArray();
            Dictionary<char, int> D = new Dictionary<char, int>();
            int a = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                D[c] = a++;
            }
            string PlaintText = "";
            string keyStream = key;
            int i = 0;
            while (key.Length < cipherText.Length)
            {
                for (char c = 'a'; c <= 'z'; c++)
                {
                    if (shiftletters[D[c], D[key[i]]] == cipherText.ToLower()[i])
                    {
                        PlaintText += c;
                        keyStream += c;
                    }
                }
                i++;
                key = keyStream;
            }
            PlaintText = "";
            for (int k = 0; k < cipherText.Length; k++)
            {
                for (char c = 'a'; c <= 'z'; c++)
                {
                    if (shiftletters[D[c], D[key[k]]] == cipherText.ToLower()[k])
                    {
                        PlaintText += c;
                    }
                }
            }
            return PlaintText;
        }
        public char[,] genArray()
        {
            char[,] arr = new char[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {

                    int let = i + j;
                    if (let >= 26)
                        let = let - 26;
                    let = let + 97;
                    char letter = (char)let;
                    arr[i, j] = letter;
                }
            }
            return arr;
        }
        public string Encrypt(string plainText, string key)
        {
            key = key.ToUpper();
            plainText = plainText.ToUpper();
            string cipher = "";
            if (key.Length < plainText.Length)
            {
                int diff = plainText.Length - key.Length;
                for (int i = 0; i < diff; i++)
                {
                    key += plainText[i];
                }

            }
            for (int i = 0; i < key.Length; i++)
            {
                cipher += Convert.ToChar((((plainText[i] - 65) + (key[i] - 65)) % 26) + 65);
            }
            return cipher;
        }
    }
}
