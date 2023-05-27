using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        static bool IsLastPermutation(int[] key)
        {

            int order = key.Length;
            if (key[0] != order) return false;
            if (key[order - 1] != 1) return false;
            for (int i = 0; i < order - 1; ++i)
            {
                if (key[i] < key[i + 1])
                    return false;
            }
            return true;
        }

        static int[] PossibleKeys(int[] key)
        {
            int order = key.Length;
            if (IsLastPermutation(key) == true)
                return null;

            int[] result = new int[order];
            for (int k = 0; k < order; ++k)
                result[k] = key[k];

            int left, right;

            left = order - 2;
            while ((result[left] > result[left + 1]) && (left >= 1))
                left--;

            right = order - 1;
            while (result[left] > result[right])
                right--;



            int tmp = result[left];
            result[left] = result[right];
            result[right] = tmp;

            int i = left + 1;
            int j = order - 1;
            while (i < j)
            {
                tmp = result[i];
                result[i++] = result[j];
                result[j--] = tmp;
            }

            return result;
        }

        public List<int> Analyse(string plainText, string cipherText)
        {

            string cipher;

            cipherText = cipherText.ToLower();
            for (int i = 2; true; i++)
            {
                int[] key = Enumerable.Range(1, i).ToArray<int>();

                while (key != null)
                {

                    cipher = Encrypt(plainText, key.ToList());
                    if (cipher == cipherText)
                    {
                        return key.ToList();
                    }
                    key = PossibleKeys(key);
                }

            }

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            // throw new NotImplementedException();
            string plainText = "";
            char[,] plain = new char[key.Count, (cipherText.Length / key.Count)];
            char[,] newplain = new char[(cipherText.Length / key.Count), key.Count];
            int col = 0, index = 0, row;

            for (row = 0; row < key.Count; row++)
            {
                for (int depth = 0; depth < (cipherText.Length / key.Count); depth++)
                {
                    plain[row, depth] = cipherText[index];
                    index++;
                }
            }

            for (int depth = 0; depth < key.Count; depth++)
            {
                for (row = 0; row < (cipherText.Length / key.Count); row++)
                {
                    newplain[row, key.IndexOf(depth + 1)] = plain[depth, row];
                }
            }
            for (int depth = 0; depth < (cipherText.Length / key.Count); depth++)
            {
                for (col = 0; col < key.Count; col++)
                {
                    plainText += newplain[depth, col];
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            string cipherText = "";
            char[,] cipher = new char[(plainText.Length / key.Count) + 1, key.Count];
            int col, index = 0, row = 0;

            for (int depth = 0; depth < (plainText.Length / key.Count) + 1; depth++)
            {
                for (col = 0; col < key.Count; col++)
                {
                    if (index < plainText.Length)
                        cipher[depth, col] = plainText[index];
                    index++;
                }
                row++;
            }

            for (int depth = 0; depth < key.Count; depth++)
            {
                for (col = 0; col < row; col++)
                {
                    if (cipher[col, key.IndexOf(depth + 1)] != '\0')
                        cipherText += cipher[col, key.IndexOf(depth + 1)];
                }
            }
            return cipherText;
        }
    }
}
