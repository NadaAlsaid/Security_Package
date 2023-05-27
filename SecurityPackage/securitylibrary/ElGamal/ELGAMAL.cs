using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public static long ModOfPower(int B, int P, int M)
        {
            if (P == 1) return B % M;
            long result = ModOfPower(B, P / 2, M);
            if (P % 2 == 0)
            {
                return (result * result) % M;
            }
            else
            {
                return (result * result * (B % M)) % M;
            }
        }
        public int GetMultiplicativeInverse(int number, int baseN)
        {

            int A1, A2, A3, B1, B2, B3, T1, T2, T3, Q;
            A1 = 1;
            A2 = 0;
            A3 = baseN;
            B1 = 0;
            B2 = 1;
            B3 = number;
            while (true)
            {
                if (B3 == 0)
                {
                    return -1;
                }
                else if (B3 == 1)
                    return ((B2 % baseN) + baseN) % baseN;

                Q = A3 / B3;
                T1 = A1 - (Q * B1);
                T2 = A2 - (Q * B2);
                T3 = A3 - (Q * B3);
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = T1;
                B2 = T2;
                B3 = T3;
            }
        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            long bigK = ModOfPower(y, k, q);
            long c1 = ModOfPower(alpha, k, q);
            long c2 = ((bigK % q)*(m % q)) % q;
            List<long> Cs = new List<long>();
            Cs.Add(c1);
            Cs.Add(c2);
            return Cs;

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int K =(int) ModOfPower(c1, x, q);
            int invK = GetMultiplicativeInverse(K, q);
            int bigM = (invK * (c2 % q))%q ;
            return bigM;

        }
    }
}
