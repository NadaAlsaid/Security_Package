using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
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
        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();
            int n = p * q;
            return (int)ModOfPower(M, e, n);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int qn = (p - 1) * (q - 1);
            ExtendedEuclid extended = new ExtendedEuclid();
            int d = extended.GetMultiplicativeInverse(e, qn);
            return (int)ModOfPower(C, d, n);
        }
    }
}
