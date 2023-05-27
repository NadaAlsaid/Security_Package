using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            char[] key = Enumerable.Repeat('^', 26).ToArray(); // loop to avoid outofrange exception and sey default value '^'
            HashSet<char> used = new HashSet<char>();     // used hash set to get unique chars

            for (int i = 0; i < cipherText.Length; i++)
            {
                int index = (int)plainText[i] - 97;

                key[index] = cipherText[i];

                used.Add(cipherText[i]);

            }

            for (int i = 0; i < 26; i++)
            {

                if (key[i] == '^') // ^ instead of null
                {

                    for (int j = 97; j <= 122; j++)
                    {
                        if (!used.Contains((char)j))
                        {
                            key[i] = (char)j;

                            used.Add((char)j);
                            break; // break for not finish all free char on same index 
                        }

                    }

                }

            }

            return new string(key).ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            int j = 0;
            cipherText = cipherText.ToLower();

            char[] plain = new char[cipherText.Length];
            for (int i = 0; i < cipherText.Length; i++)
            {

                j = (key.IndexOf(cipherText[i])) + 97;

                plain[i] = (Char)j;

            }

            return new string(plain);
        }

        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            char[] cipher = plainText.ToCharArray();
            for (int i = 0; i < plainText.Length; i++)
            {

                int j = plainText[i] - 97;

                cipher[i] = key[j];

            }


            return new string(cipher);

        }


        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            // throw new NotImplementedException();
            string key = "";
            SortedDictionary<char, int> frequency = new SortedDictionary<char, int>();
            for (int i = 0; i < cipher.Length; i++)
            {
                if (frequency.ContainsKey(cipher[i]))
                {
                    frequency[cipher[i]]++;
                }
                else
                {
                    frequency.Add(cipher[i], 1);
                }
            }
            var ordered = frequency.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            List<int> list = ordered.Values.ToList();
            char[] elementFrequency = { 'E' ,'T' ,'A' ,'O' ,'I' ,'N','S','R' ,
                'H', 'L', 'D' ,'C'  ,'U','M', 'F','P','G' ,'W'  ,'Y' , 'B','V', 'K' ,
                'X' , 'J' , 'Q' , 'Z'};

            for (int i = 0; i < cipher.Length; i++)
            {
                int d = ordered[cipher[i]];

                key += elementFrequency[list.IndexOf(d)];
            }
            return key;
        }
    }

}
