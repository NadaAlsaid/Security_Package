using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {


        public int Mod(int baze, int pow, int mod)
        {
            int result = 1;
            for (int i = 0; i < pow; ++i)
            {
                result = ((result * baze) % mod);


            }
            return result;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //  throw new NotImplementedException();


            int ya = Mod(alpha, xa, q);
            int yb = Mod(alpha, xb, q);


            int k1 = Mod(yb, xa, q);
            int k2 = Mod(ya, xb, q);


            return new List<int>() { k1, k2 };
        }
    }
}
