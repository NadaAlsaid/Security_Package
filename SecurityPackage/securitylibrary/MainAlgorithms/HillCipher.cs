using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        int[,] ListTomatrix;
        int[,] m2m = new int[2, 2];
        int[,] container = new int[2, 2];
        int[,] m3m = new int[3, 3];
        int[,] transpose = new int[3, 3];
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int[,] plain = new int[2, plainText.Count / 2];
            int[,] cipher = new int[2, plainText.Count / 2];
            int[,] key = new int[2, 2];
            int c = 0;
            for (int i = 0; i < plainText.Count / 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    if (c == plainText.Count)
                        break;
                    plain[j, i] = plainText[c];
                    c++;
                }
            }
            c = 0;
            for (int i = 0; i < plainText.Count / 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    if (c == plainText.Count)
                        break;
                    cipher[j, i] = cipherText[c];
                    c++;
                }
            }



            for (int i = 0; i < plainText.Count / 2; i++)
            {
                for (int row = 0; row < 2; row++)
                {
                    m2m[row, 0] = plain[row, i];
                }

                for (int j = i + 1; j < plainText.Count / 2; j++)
                {
                    for (int row = 0; row < 2; row++)
                    {
                        m2m[row, 1] = plain[row, j];
                    }
                    if (GCD(26, (int)Find_determinant(m2m, 2) % 26) == 1)
                    {
                        for (int row = 0; row < 2; row++)
                        {
                            container[row, 0] = cipher[row, i];
                            container[row, 1] = cipher[row, j];
                        }
                        int[,] inverse = findInverseMatrix_2x2(m2m);
                        for (int cm = 0; cm < 2; cm++)
                        {
                            for (int gc = 0; gc < 2; gc++)
                            {
                                int temp = 0;
                                for (int k = 0; k < 2; k++)
                                {
                                    temp += this.container[cm, k] * inverse[k, gc];
                                }
                                key[cm, gc] = temp;
                                key[cm, gc] %= 26;
                            }

                        }
                        break;
                    }

                }
                break;
            }
            List<int> returnkey = new List<int>();
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    returnkey.Add(key[i, j]);
                }
            }

            if (returnkey[0] == 0 && returnkey[1] == 0 && returnkey[2] == 0 && returnkey[3] == 0)
                throw new InvalidAnlysisException();
            return returnkey;
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int m = (int)Math.Sqrt(key.Count);
            int[,] keyMatrix = generateKeyMatrix(key, m);

            int det = calcDet(keyMatrix);
            int b = calcB(det);
            if (!hasInverse(keyMatrix, det, b))
                throw new InvalidAnlysisException();
            List<int> keyInverseMatrix = generateKeyInverseMatrix(keyMatrix, b);

            List<int> answer = Encrypt(cipherText, keyInverseMatrix);

            return answer;

        }
        public static int[,] generateKeyMatrix(List<int> key, int rowsNumber)
        {
            int colsNumber = key.Count / rowsNumber;
            int[,] keyMatrix = new int[rowsNumber, colsNumber];

            int i = 0;
            for (int r = 0; r < rowsNumber; r++)
                for (int c = 0; c < colsNumber; c++)
                    keyMatrix[r, c] = key[i++];

            return keyMatrix;
        }
        public static int calcDet(int[,] key)
        {
            int det;
            int size = key.GetLength(0);
            if (size == 2)
            {
                det = key[0, 0] * key[1, 1] - key[0, 1] * key[1, 0];
            }
            else
            {
                det = key[0, 0] * ((key[1, 1] * key[2, 2]) - (key[1, 2] * key[2, 1])) -
                       key[0, 1] * ((key[1, 0] * key[2, 2]) - (key[1, 2] * key[2, 0])) +
                       key[0, 2] * ((key[1, 0] * key[2, 1]) - (key[1, 1] * key[2, 0]));
            }
            if (det % 26 < 0)
            {
                det %= 26;
                det += 26;
                return det;
            }

            return det % 26;
        }
        public static int calcB(int det)
        {
            for (int i = 1; i < 26; i++)
                if ((i * det) % 26 == 1)
                    return i;

            return -1;
        }

        public static bool hasInverse(int[,] keyMatrix, int det, int b)
        {
            bool nonnegative = true;
            bool hasGCD = true;
            bool hasB = true;
            bool det_not_zero = true;
            for (int r = 0; r < keyMatrix.GetLength(0); r++)
            {
                for (int c = 0; c < keyMatrix.GetLength(1); c++)
                {
                    if (keyMatrix[r, c] < 0 || keyMatrix[r, c] > 26)
                    {
                        nonnegative = false;
                        break;
                    }
                }
                if (nonnegative == false)
                    break;
            }
            if (GCD(det, 26) != 1)
                hasGCD = false;
            if (b > 26 || (b * det) % 26 != 1)
                hasB = false;
            if (det == 0)
                det_not_zero = false;
            if (nonnegative && hasGCD && hasB && det_not_zero)
                return true;
            return false;
        }
        public static int[,] generateSubMatrix(int[,] key, int row, int col)
        {
            int[,] subMatrix = new int[key.GetLength(0) - 1, key.GetLength(1) - 1];

            List<int> numsToTake = new List<int>();

            for (int r = 0; r < key.GetLength(0); r++)
            {
                for (int c = 0; c < key.GetLength(1); c++)
                {
                    if (r == row || c == col)
                        continue;

                    numsToTake.Add(key[r, c]);
                }
            }

            subMatrix = generateKeyMatrix(numsToTake, (int)Math.Sqrt(numsToTake.Count));
            return subMatrix;
        }
        public static int GCD(int a, int b)
        {
            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }

            return a | b;
        }
        public static List<int> generateKeyInverseMatrix(int[,] key, int b)
        {
            int k = 0, det = 0;
            List<int> vals = new List<int>();

            int[,] inversekeyMatrix = new int[key.GetLength(0), key.GetLength(1)];

            if (key.GetLength(0) == 2)
            {
                int tmp = key[0, 0];
                key[0, 0] = key[1, 1];
                key[1, 1] = tmp;

                key[0, 1] *= -1;
                key[1, 0] *= -1;

                inversekeyMatrix = key;

                tmp = 0;
                for (int r = 0; r < inversekeyMatrix.GetLength(0); r++)
                {
                    for (int c = 0; c < inversekeyMatrix.GetLength(1); c++)
                    {
                        tmp = (b * inversekeyMatrix[r, c]) % 26;
                        if (tmp < 0)
                        {
                            tmp += 26;
                        }
                        vals.Add(tmp);
                    }
                }
                int valsIndexer = 0;
                for (int r = 0; r < key.GetLength(0); r++)
                    for (int c = 0; c < key.GetLength(1); c++)
                        inversekeyMatrix[r, c] = vals[valsIndexer++];

            }

            else
            {
                for (int r = 0; r < key.GetLength(0); r++)
                {
                    for (int c = 0; c < key.GetLength(1); c++)
                    {

                        if (key.GetLength(0) == 2)
                        {
                            det = calcDet(key);
                        }
                        else
                        {
                            det = calcDet(generateSubMatrix(key, r, c));
                        }

                        k = (b * (int)Math.Pow(-1, r + c) * det) % 26;

                        if (k < 0)
                        {
                            k += 26;
                        }
                        vals.Add(k);
                    }
                }
                int valsIndexer = 0;
                for (int c = 0; c < key.GetLength(1); c++)
                    for (int r = 0; r < key.GetLength(0); r++)
                        inversekeyMatrix[r, c] = vals[valsIndexer++];
            }
            List<int> inverseKeyList = new List<int>();
            for (int r = 0; r < inversekeyMatrix.GetLength(0); r++)
            {
                for (int c = 0; c < inversekeyMatrix.GetLength(1); c++)
                {
                    inverseKeyList.Add(inversekeyMatrix[r, c]);
                }
            }
            return inverseKeyList;
        }
       
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherText = new List<int>();
            int m = calcSqrt(key.Count);
            List<List<int>> keyMatrix = makeKeyMatrix(key, m);
            List<List<int>> plainTextMatrix = makeTextMatrix(plainText, m);
            for (int i = 0; i < plainText.Count / m; i++)
            {
                List<int> tmp = multiplyMatrix(keyMatrix, plainTextMatrix[i], m);
                for (int j = 0; j < m; j++)
                {
                    cipherText.Add(tmp[j]);
                }
            }
            return cipherText;
        }
         private int calcSqrt(int nmbr)
        {
            if (nmbr == 0)
            {
                return 0;
            }
            else if (nmbr == 1)
            {
                return 1;
            }
            int i;
            for (i = 0; i < nmbr / 2; i++)
            {
                if (i * i == nmbr)
                {
                    break;
                }
            }
            return i;
        }
        private List<List<int>> makeKeyMatrix(List<int> key, int m)
        {
            List<List<int>> matrix = new List<List<int>>();
            int k = 0;
            for (int i = 0; i < m; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    tmp.Add(key[k]);
                    k++;
                }
                matrix.Add(tmp);
            }
            return matrix;
        }
        private List<List<int>> makeTextMatrix(List<int> text, int m)
        {
            List<List<int>> matrix = new List<List<int>>();
            int k = 0;
            for (int i = 0; i < text.Count / m; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    tmp.Add(text[k]);
                    k++;
                }
                matrix.Add(tmp);
            }
            return matrix;
        }
        private List<int> multiplyMatrix(List<List<int>> key, List<int> plainText, int m)
        {
            List<int> res = new List<int>();
            for (int i = 0; i < m; i++)
            {
                int tmp = 0;
                for (int j = 0; j < m; j++)
                {
                    tmp += key[i][j] * plainText[j];
                }
                tmp = tmp % 26;
                while (tmp < 0)
                {
                    tmp += 26;
                }
                res.Add(tmp);
            }
            return res;
        }
        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int cm = 0;
            int[,] m3m = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (cm == plainText.Count)
                        break;
                    m3m[j, i] = plainText[cm];
                    cm++;
                }
            }
            cm = 0;
            int[,] mx2m = new int[3, 3];
            int[,] key = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (cm == plainText.Count)
                        break;
                    mx2m[j, i] = cipherText[cm];
                    cm++;
                }
            }
            ListTomatrix = m3m;
            findInverseMatrix_3x3();
            findTransposeMatrix();
            int[,] inverse = transpose;
            for (int i = 0; i < 3; i++)
            {
                for (int c = 0; c < 3; c++)
                {
                    int temp = 0;
                    for (int k = 0; k < 3; k++)
                    {
                        temp += mx2m[i, k] * inverse[k, c];
                    }
                    key[i, c] = temp;
                    key[i, c] %= 26;
                }

            }
            List<int> returnkey = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    returnkey.Add(key[i, j]);
                }
            }
            if (returnkey[0] == 0 && returnkey[1] == 0 && returnkey[2] == 0 && returnkey[3] == 0)
                throw new InvalidAnlysisException();
            return returnkey;
        }
        public void Convert_ListToMatrix(List<int> list, int rowcol)
        {
            int counter = 0;
            ListTomatrix = new int[rowcol, rowcol];
            for (int i = 0; i < rowcol; i++)
            {
                for (int j = 0; j < rowcol; j++)
                {
                    ListTomatrix[i, j] = list[counter];
                    counter++;
                }
            }
        }
        public void findInverseMatrix_3x3()
        {
         
            double det = Find_determinant(ListTomatrix, 3);
            while (det < 0)
                det += 26;
            int b = Multiplicative_Inverse(Convert.ToInt32(det), 26);

            int h = 0, y = 0, counter = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    for (int k = 0; k < 3; k++)
                    {
                        for (int mx = 0; mx < 3; mx++)
                        {
                            if (mx != j && k != i)
                            {
                                m2m[h, y] = ListTomatrix[k, mx];
                                counter++;
                                y++;
                                if (counter == 2)
                                {
                                    h++;
                                    y = 0;
                                }
                            }
                        }
                    }
                    counter = 0;
                    h = 0; y = 0;
                    double sign = Math.Pow(-1, i + j);
                    int value = b * Convert.ToInt32(sign) * Convert.ToInt32(Find_determinant(m2m, 2)) % 26;
                    if (value < 0)
                        value += 26;
                    m3m[i, j] = value;
                }
            }
        }
        public void findTransposeMatrix()
        {
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    transpose[j, i] = m3m[i, j];
                }
            }

        }
        public void findInverseMatrix_2x2()
        {
            m2m[0, 0] = ListTomatrix[1, 1];
            m2m[0, 1] = -1 * ListTomatrix[0, 1];
            m2m[1, 0] = -1 * ListTomatrix[1, 0];
            m2m[1, 1] = ListTomatrix[0, 0];


            //find determenant of the matrix
            double det = Find_determinant(ListTomatrix, 2);
            while (det < 0)
                det += 26;
            int x = Multiplicative_Inverse((int)det, 26);
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    m2m[i, j] = x * m2m[i, j];
                }
            }

        }
        static public int[,] findInverseMatrix_2x2(int[,] m)
        {
            int[,] m2m = new int[2, 2];
            m2m[0, 0] = m[1, 1];
            m2m[0, 1] = -1 * m[0, 1];
            m2m[1, 0] = -1 * m[1, 0];
            m2m[1, 1] = m[0, 0];


            //find determenant of the matrix
            double det = Find_determinant(m, 2) % 26;
            while (det < 0)
                det += 26;
            int x = Multiplicative_Inverse((int)det, 26);

            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    m2m[i, j] = x * m2m[i, j];
                    m2m[i, j] %= 26;

                }

            }
            return m2m;
        }
        static public double Find_determinant(int[,] A, int N)
        {
            double res;
            if (N == 1)
                res = A[0, 0];
            else if (N == 2)
            {
                res = A[0, 0] * A[1, 1] - A[1, 0] * A[0, 1];
            }
            else
            {
                res = 0;
                for (int j1 = 0; j1 < N; j1++)
                {
                    int[,] m = new int[N - 1, N - 1];
                    for (int i = 1; i < N; i++)
                    {
                        int j2 = 0;
                        for (int j = 0; j < N; j++)
                        {
                            if (j == j1)
                                continue;
                            m[i - 1, j2] = A[i, j];
                            j2++;
                        }
                    }
                    res += Math.Pow(-1.0, 1.0 + j1 + 1.0) * A[0, j1] * Find_determinant(m, N - 1);
                }
            }
            return res;


        }
        static public int Multiplicative_Inverse(int det, int B3)
        {
            for (int i = 1; i < 27; i++)
            {
                int c = i * det % B3;
                if (c == 1)
                {
                    return i;
                }
            }
            return 0;
        }
       
    }
    }
