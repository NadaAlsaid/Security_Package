using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";
            char[,] matrix = new char[5, 5];
            int counter = 0;
            char[] alphabet = "abcdefghiklmnopqrstuvwxyz".ToCharArray();
            StringBuilder newkey = new StringBuilder(); 
            key = key.Replace("j", "i");
            foreach (char c in key)
            {
                if (!newkey.ToString().Contains(c))
                {
                    newkey.Append(c);
                    alphabet = alphabet.Where(value => value != c).ToArray(); 
                }
            }
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (newkey.Length != 0)
                    {

                        matrix[i, j] = newkey[0];

                        newkey.Remove(0, 1);


                    }
                    else
                    {
                        matrix[i, j] = alphabet[counter];
                        counter++;
                    }
                }
            }

            bool char1;

            int index, indexRow;
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                index = 0;
                char1 = false;
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[index, j] == cipherText[i])
                    {
                        indexRow = 0;
                        for (int k = 0; k < 5; k++)
                        {
                            if (matrix[index, k] == cipherText[i + 1])
                            {
                                plainText += matrix[index, Math.Abs(j - 1 + 5) % 5];
                                plainText += matrix[index, (k - 1 + 5) % 5];
                                char1 = true;
                                break;
                            }
                            else if (matrix[k, j] == cipherText[i + 1])
                            {
                                plainText += matrix[Math.Abs(index - 1 + 5) % 5, j];
                                plainText += matrix[Math.Abs(k - 1 + 5) % 5, j];

                                char1 = true;
                                break;
                            }
                            else if (matrix[indexRow, k] == cipherText[i + 1])
                            {
                                plainText += matrix[index, k];
                                plainText += matrix[indexRow, j];

                                char1 = true;
                                break;
                            }

                            if (k + 1 == 5 && indexRow < 5)
                            {
                                k = -1;
                                indexRow++;
                            }
                        }

                    }
                    if (char1)
                        break;
                    if (j + 1 == 5 && index < 5)
                    {
                        j = -1;
                        index++;
                    }

                }

            }
            if (plainText[plainText.Length - 1] == 'x')
            {
                plainText = plainText.Remove(plainText.Length - 1, 1);
            }

            for (int i = 1; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i + 1] == plainText[i - 1] && plainText[i] == 'x')
                {

                    plainText = plainText.Remove(i, 1);
                    i++;
                }
                else if (plainText[i + 1] == plainText[i - 1] && plainText[i] == 'q')
                {
                    plainText = plainText.Remove(i, 1);
                    i++;
                }


            }

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {


           
            plainText = plainText.ToLower();

            List<char> plainText_pairs = new List<char>();

            for (int i = 0; i < plainText.Length; i++)
            {
                if (i + 1 < plainText.Length)
                {
                    if (plainText[i] == plainText[i + 1] && plainText[i] != 'x')
                    {
                        plainText_pairs.Add(plainText[i]);
                        plainText_pairs.Add('x');

                    }
                    else if (plainText[i] == plainText[i + 1] && plainText[i] == 'x')
                    {
                        plainText_pairs.Add(plainText[i]);
                        plainText_pairs.Add('q');

                    }
                    else
                    {
                        plainText_pairs.Add(plainText[i]);
                        plainText_pairs.Add(plainText[i + 1]);
                        i++;
                    }
                }
                else
                {
                    plainText_pairs.Add(plainText[i]);
                }


            }

            if ((plainText_pairs.Count % 2 > 0))    

            {
                plainText_pairs.Add('x');
            }

            char[] alphabet = "abcdefghiklmnopqrstuvwxyz".ToCharArray();
            StringBuilder newkey = new StringBuilder(); 

            key = key.Replace("j", "i");
            foreach (char c in key)
            {
                if (!newkey.ToString().Contains(c))
                {
                    newkey.Append(c);
                    alphabet = alphabet.Where(value => value != c).ToArray(); 
                }
            }

            char[,] matrix = new char[5, 5];
            int counter = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (newkey.Length != 0)
                    {

                        matrix[i, j] = newkey[0];

                        newkey.Remove(0, 1);


                    }
                    else
                    {
                        matrix[i, j] = alphabet[counter];
                        counter++;
                    }
                }
            }



            bool char1;
            string cipherText = "";
            int index, indexRow;
            for (int i = 0; i < plainText_pairs.Count; i += 2)
            {
                index = 0;
                char1 = false;
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[index, j] == plainText_pairs[i])
                    {
                        indexRow = 0;
                        for (int k = 0; k < 5; k++)
                        {
                            if (matrix[index, k] == plainText_pairs[i + 1])
                            {
                                cipherText += matrix[index, (j + 1) % 5];
                                cipherText += matrix[index, (k + 1) % 5];
                                char1 = true;
                                break;
                            }
                            else if (matrix[k, j] == plainText_pairs[i + 1])
                            {
                                cipherText += matrix[(index + 1) % 5, j];
                                cipherText += matrix[(k + 1) % 5, j];

                                char1 = true;
                                break;
                            }
                            else if (matrix[indexRow, k] == plainText_pairs[i + 1])
                            {
                                cipherText += matrix[index, k];
                                cipherText += matrix[indexRow, j];

                                char1 = true;
                                break;
                            }

                            if (k + 1 == 5 && indexRow < 5)
                            {
                                k = -1;
                                indexRow++;
                            }
                        }

                    }
                    if (char1)
                        break;
                    if (j + 1 == 5 && index < 5)
                    {
                        j = -1;
                        index++;
                    }

                }

            }

            return cipherText;
        }
    }
    }
