using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.MD5
{

    public class MD5
    {

        Dictionary<int, int[]> S = new Dictionary<int, int[]>()
        {
            {1 , new int[]{ 7,12,17,22}  } ,
            {2 , new int[]{ 5,9,14,20}  } ,
            {3 , new int[]{ 4,11,16,23}  } ,
            {4 , new int[]{ 6,10,15,21}  }
        };
        public static uint R(uint x, int c)
        {
            return (x << c) | (x >> (32 - c));
        }
        static uint F(uint B, uint C, uint D)
        {
            uint Fres = (B & C) | ((~B) & D);
            return Fres;

        }
        static uint G(uint B, uint C, uint D)
        {

            uint Gres = (B & D) | (C & (~D));
            return Gres;

        }
        static uint H(uint B, uint C, uint D)
        {

            uint Hres = (B ^ C) ^ D;
            return Hres;

        }
        static uint I(uint B, uint C, uint D)
        {

            uint Ires = C ^ (B | (~D));
            return Ires;

        }
        void Round_16(ref uint A, ref uint B, ref uint C, ref uint D, int numberOfRound, uint[] Y)
        {
            uint result = 0, T = 0;
            for (int i = 0; i < 16; i++)
            {

                switch (numberOfRound)
                {
                    case 1:
                        result = F(B, C, D);
                        break;
                    case 2:
                        result = G(B, C, D);
                        break;
                    case 3:
                        result = H(B, C, D);
                        break;
                    case 4:
                        result = I(B, C, D);
                        break;
                }
                result = ((A + result));
                switch (numberOfRound)
                {
                    case 1:
                        result = ((Y[i] + result));
                        break;
                    case 2:
                        result = ((Y[(1 + 5 * ((16 * (numberOfRound - 1)) + i)) % 16] + result));
                        break;
                    case 3:
                        result = ((Y[(5 + 3 * ((16 * (numberOfRound - 1)) + i)) % 16] + result));
                        break;
                    case 4:
                        result = ((Y[(7 * ((16 * (numberOfRound - 1)) + i)) % 16] + result));
                        break;
                }

                T = (uint)(Math.Pow(2, 32) * Math.Abs(Math.Sin(((16 * (numberOfRound - 1)) + i + 1))));
                result = (T + result);
                result = B + R(result, S[numberOfRound][(i % 4)]);
                A = D;
                D = C;
                C = B;
                B = result;
            }

        }
       
        public string GetHash(string text)
        {

            String cipherText;  
            byte[] plaintext = Encoding.ASCII.GetBytes(text);
            long Length_in_bits = plaintext.Length * 8; 
            int Length_of_padding = (Math.Abs(448 - ((int)Length_in_bits % 512))) % 512; 
            int Length_of_padding_in_bytes = Length_of_padding / 8; 
            byte[] padded_Message = new byte[plaintext.Length + Length_of_padding_in_bytes + 8]; 
            Array.Copy(plaintext, padded_Message, plaintext.Length);
            padded_Message[plaintext.Length] = 0x80;            
            for (int i = plaintext.Length + 1; i < padded_Message.Length - 8; i++)
            {
                padded_Message[i] = 0x00;
            }
            for (int i = 0; i < 8; i++) 
            {
                padded_Message[padded_Message.Length - 8 + i] = (byte)(Length_in_bits >> (i * 8));
            }
            uint A_init = 0x67452301;   
            uint B_init = 0xefcdab89;   
            uint C_init = 0x98badcfe;   
            uint D_init = 0x10325476;   
            for (int i = 0; i < padded_Message.Length / 64; ++i)
            {
                uint[] m = new uint[16];
                for (int j = 0; j < 16; ++j)
                    m[j] = BitConverter.ToUInt32(padded_Message, (i * 64) + (j * 4));
             
                uint A = A_init, B = B_init, C =C_init, D = D_init;

                for (int round = 0; round < 4; round++)
                {
                    Round_16(ref A, ref B, ref C, ref D, round + 1, m);
                }

                A_init += A;
                B_init += B;
                C_init += C;
                D_init += D;
            }
            cipherText = BytesToString(A_init) + BytesToString(B_init) + BytesToString(C_init) + BytesToString(D_init);
            return cipherText;
        }

        private static string BytesToString(uint register_Value)
        {
            return String.Join("", BitConverter.GetBytes(register_Value).Select(y => y.ToString("x2")));
        }
    }
}