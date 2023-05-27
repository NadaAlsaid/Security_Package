using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        /*string[ , ] sbox = {
                { "0x63", "0x7c", "0x77", "0x7b", "0xf2", "0x6b", "0x6f", "0xc5", "0x30", "0x01", "0x67", "0x2b", "0xfe", "0xd7", "0xab", "0x76" },
                { "0xca", "0x82", "0xc9", "0x7d", "0xfa", "0x59", "0x47", "0xf0", "0xad", "0xd4", "0xa2", "0xaf", "0x9c", "0xa4", "0x72", "0xc0" },
                { "0xb7", "0xfd", "0x93", "0x26", "0x36", "0x3f", "0xf7", "0xcc", "0x34", "0xa5", "0xe5", "0xf1", "0x71", "0xd8", "0x31", "0x15" },
                { "0x04", "0xc7", "0x23", "0xc3", "0x18", "0x96", "0x05", "0x9a", "0x07", "0x12", "0x80", "0xe2", "0xeb", "0x27", "0xb2", "0x75"},
                { "0x09", "0x83", "0x2c", "0x1a", "0x1b", "0x6e", "0x5a", "0xa0", "0x52", "0x3b", "0xd6", "0xb3", "0x29", "0xe3", "0x2f", "0x84" },
                { "0x53", "0xd1", "0x00", "0xed", "0x20", "0xfc", "0xb1", "0x5b", "0x6a", "0xcb", "0xbe", "0x39", "0x4a", "0x4c", "0x58", "0xcf" },
                { "0xd0", "0xef", "0xaa", "0xfb", "0x43", "0x4d", "0x33", "0x85", "0x45", "0xf9", "0x02", "0x7f", "0x50", "0x3c", "0x9f", "0xa8" },
                { "0x51", "0xa3", "0x40", "0x8f", "0x92", "0x9d", "0x38", "0xf5", "0xbc", "0xb6", "0xda", "0x21", "0x10", "0xff", "0xf3", "0xd2" },
                { "0xcd", "0x0c", "0x13", "0xec", "0x5f", "0x97", "0x44", "0x17", "0xc4", "0xa7", "0x7e", "0x3d", "0x64", "0x5d", "0x19", "0x73"},
                { "0x60", "0x81", "0x4f", "0xdc", "0x22", "0x2a", "0x90", "0x88", "0x46", "0xee", "0xb8", "0x14", "0xde", "0x5e", "0x0b", "0xdb"},
                { "0xe0", "0x32", "0x3a", "0x0a", "0x49", "0x06", "0x24", "0x5c", "0xc2", "0xd3", "0xac", "0x62", "0x91", "0x95", "0xe4", "0x79"},
                { "0xe7", "0xc8", "0x37", "0x6d", "0x8d", "0xd5", "0x4e", "0xa9", "0x6c", "0x56", "0xf4", "0xea", "0x65", "0x7a", "0xae", "0x08"},
                { "0xba", "0x78", "0x25", "0x2e", "0x1c", "0xa6", "0xb4", "0xc6", "0xe8", "0xdd", "0x74", "0x1f", "0x4b", "0xbd", "0x8b", "0x8a"},
                { "0x70", "0x3e", "0xb5", "0x66", "0x48", "0x03", "0xf6", "0x0e", "0x61", "0x35", "0x57", "0xb9", "0x86", "0xc1", "0x1d", "0x9e"},
                { "0xe1", "0xf8", "0x98", "0x11", "0x69", "0xd9", "0x8e", "0x94", "0x9b", "0x1e", "0x87", "0xe9", "0xce", "0x55", "0x28", "0xdf"},
                { "0x8c", "0xa1", "0x89", "0x0d", "0xbf", "0xe6", "0x42", "0x68", "0x41", "0x99", "0x2d", "0x0f", "0xb0", "0x54", "0xbb", "0x16"} };
        */
        static int[] Rcon = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
        int[,] matrixMaxColumns = {
            {0x02 , 0x03 , 0x01 , 0x01 },
            {0x01 , 0x02 , 0x03 , 0x01 },
            {0x01 , 0x01 , 0x02 , 0x03 },
            {0x03 , 0x01 , 0x01 , 0x02 }
        };
        int[,] INVmatrixMaxColumns = {
            {0x0E , 0x0B , 0x0D , 0x09 },
            {0x09 , 0x0E , 0x0B , 0x0D },
            {0x0D , 0x09 , 0x0E , 0x0B },
            {0x0B , 0x0D , 0x09 , 0x0E }
        };
        int[,] sbox = {
                { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
                { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
                { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
                { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
                { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
                { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
                { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
                { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
                { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
                { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
                { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
                { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
                { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
                { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
                { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
                { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
        };
        int[,] inv_sbox = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB },//0
  { 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},//1
  { 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E },//2
  { 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 },//3
  { 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 },//4
  { 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 },//5
  { 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 },//6
  { 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B },//7
  { 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 },//8
  { 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E },//9
  { 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B },//A
  { 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 },//B
  { 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F },//C
  { 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF },//D
  { 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 },//E
  { 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D } }; //F
        public int[,] KeyScheduleRevese(int[,] key, int index_Rcon)
        {
            int[,] roundkey = new int[4, 4];
            int[] firstColumn = new int[4];
            string s, s2;
            int result;
            for (int i = 0; i < 4; i++)
            {
                result = key[(i + 1) % 4, 3] / 16;
                firstColumn[i] = sbox[(result), key[(i + 1) % 4, 3] - result * 16];
            }

            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {

                    if (col != 0)
                    {


                        roundkey[row, col] = key[row, col] ^ roundkey[row, col - 1];
                    }
                    else
                    {
                        if (row != 0)
                        {
                            roundkey[row, col] = key[row, col] ^ firstColumn[row] ^ 0; //(s[0]) ^ firstColumn[j];
                        }
                        else
                        {
                            roundkey[row, col] = key[row, col] ^ firstColumn[row] ^ Rcon[index_Rcon];
                        }
                    }
                }
            }
            return roundkey;
        }
        private int[,] MixColunms(int[,] plainText, int[,] matrixMaxColumns)
        {
            int i, j, k;
            int[,] plainMix = new int[4, 4];
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    for (k = 0; k < 4; k++)
                    {
                        byte x = (byte)plainText[k, j], z;
                        z = x;
                        if (matrixMaxColumns[i, k] == 2)
                        {
                            x <<= 1;
                            if (z >= 128)
                                x ^= 27;
                        }
                        else if (matrixMaxColumns[i, k] == 3)
                        {
                            x <<= 1;
                            if (z >= 128)
                                x ^= 27;
                            z = (byte)plainText[k, j];
                            x = (byte)(x ^ z);

                        }
                        plainMix[i, j] ^= x;
                    }

                }
            }
            return plainMix;
        }
        // inverse Mix Part


        void repTable1()
        {
            Table1 = new string[16, 16]
                {
            { "01", "03", "05", "0F", "11", "33", "55", "FF", "1A", "2E", "72", "96", "A1", "F8", "13", "35"},
            { "5F", "E1", "38", "48", "D8", "73", "95", "A4", "F7", "02", "06", "0A", "1E", "22", "66", "AA"},
            { "E5", "34", "5C", "E4", "37", "59", "EB", "26", "6A", "BE", "D9", "70", "90", "AB", "E6", "31"},
            { "53", "F5", "04", "0C", "14", "3C", "44", "CC", "4F", "D1", "68", "B8", "D3", "6E", "B2", "CD"},
            { "4C", "D4", "67", "A9", "E0", "3B", "4D", "D7", "62", "A6", "F1", "08", "18", "28", "78", "88"},
            { "83", "9E", "B9", "D0", "6B", "BD", "DC", "7F", "81", "98", "B3", "CE", "49", "DB", "76", "9A"},
            { "B5", "C4", "57", "F9", "10", "30", "50", "F0", "0B", "1D", "27", "69", "BB", "D6", "61", "A3"},
            { "FE", "19", "2B", "7D", "87", "92", "AD", "EC", "2F", "71", "93", "AE", "E9", "20", "60", "A0"},
            { "FB", "16", "3A", "4E", "D2", "6D", "B7", "C2", "5D", "E7", "32", "56", "FA", "15", "3F", "41"},
            { "C3", "5E", "E2", "3D", "47", "C9", "40", "C0", "5B", "ED", "2C", "74", "9C", "BF", "DA", "75"},
            { "9F", "BA", "D5", "64", "AC", "EF", "2A", "7E", "82", "9D", "BC", "DF", "7A", "8E", "89", "80"},
            { "9B", "B6", "C1", "58", "E8", "23", "65", "AF", "EA", "25", "6F", "B1", "C8", "43", "C5", "54"},
            { "FC", "1F", "21", "63", "A5", "F4", "07", "09", "1B", "2D", "77", "99", "B0", "CB", "46", "CA" },
            { "45", "CF", "4A", "DE", "79", "8B", "86", "91", "A8", "E3", "3E", "42", "C6", "51", "F3", "0E"},
            { "12", "36", "5A", "EE", "29", "7B", "8D", "8C", "8F", "8A", "85", "94", "A7", "F2", "0D", "17"},
            { "39", "4B", "DD", "7C", "84", "97", "A2", "FD", "1C", "24", "6C", "B4", "C7", "52", "F6", "01"}
            };
        }
        string[,] Table2;
        void repTable2()
        {
            Table2 = new string[16, 16] {
            { "","00", "19", "01", "32", "02", "1A", "C6", "4B", "C7", "1B", "68", "33", "EE", "DF", "03"},
            { "64", "04", "E0", "0E", "34", "8D", "81", "EF", "4C", "71", "08", "C8", "F8", "69", "1C", "C1"},
            { "7D", "C2", "1D", "B5", "F9", "B9", "27", "6A", "4D", "E4", "A6", "72", "9A", "C9", "09", "78"},
            { "65", "2F", "8A", "05", "21", "0F", "E1", "24", "12", "F0", "82", "45", "35", "93", "DA", "8E"},
            { "96", "8F", "DB", "BD", "36", "D0", "CE", "94", "13", "5C", "D2", "F1", "40", "46", "83", "38"},
            { "66", "DD", "FD", "30", "BF", "06", "8B", "62", "B3", "25", "E2", "98", "22", "88", "91", "10"},
            { "7E", "6E", "48", "C3", "A3", "B6", "1E", "42", "3A", "6B", "28", "54", "FA", "85", "3D", "BA"},
            { "2B", "79", "0A", "15", "9B", "9F", "5E", "CA", "4E", "D4", "AC", "E5", "F3", "73", "A7", "57"},
            { "AF", "58", "A8", "50", "F4", "EA", "D6", "74", "4F", "AE", "E9", "D5", "E7", "E6", "AD", "E8"},
            { "2C", "D7", "75", "7A", "EB", "16", "0B", "F5", "59", "CB", "5F", "B0", "9C", "A9", "51", "A0" },
            { "7F", "0C", "F6", "6F", "17", "C4", "49", "EC", "D8", "43", "1F", "2D", "A4", "76", "7B", "B7"},
            { "CC", "BB", "3E", "5A", "FB", "60", "B1", "86", "3B", "52", "A1", "6C", "AA", "55", "29", "9D"},
            { "97", "B2", "87", "90", "61", "BE", "DC", "FC", "BC", "95", "CF", "CD", "37", "3F", "5B", "D1"},
            { "53", "39", "84", "3C", "41", "A2", "6D", "47", "14", "2A", "9E", "5D", "56", "F2", "D3", "AB"},
            { "44", "11", "92", "D9", "23", "20", "2E", "89", "B4", "7C", "B8", "26", "77", "99", "E3", "A5"},
            { "67", "4A", "ED", "DE", "C5", "31", "FE", "18", "0D", "63", "8C", "80", "C0", "F7", "70", "07"}
            };
        }
        string[,] Table1;
        string mulInverseMixColumn(string pt1, string pt2)
        {
            repTable1();
            repTable2();
            if (pt1.Length < 2) pt1 = "0" + pt1;
            if (pt2.Length < 2) pt2 = "0" + pt2;
            if (pt1 == "00" || pt2 == "00") return "00";
            int row1 = Convert.ToInt32(pt1.Substring(0, 1), 16);
            int col1 = Convert.ToInt32(pt1.Substring(1, 1), 16);

            int row2 = Convert.ToInt32(pt2.Substring(0, 1), 16);
            int col2 = Convert.ToInt32(pt2.Substring(1, 1), 16);

            int sum = Convert.ToInt32(Table2[row1, col1], 16) + Convert.ToInt32(Table2[row2, col2], 16);
            if (sum > Convert.ToInt32("FF", 16))
            {
                sum = sum - Convert.ToInt32("FF", 16);
            }
            string ans = sum.ToString("X2");
            int row = Convert.ToInt32(ans.Substring(0, 1), 16);
            int col = Convert.ToInt32(ans.Substring(1, 1), 16);
            return Table1[row, col];
        }
        readonly string[,] invMixColumns = new string[4, 4] { { "0e", "0b", "0d", "09" }, { "09", "0e", "0b", "0d" }, { "0d", "09", "0e", "0b" }, { "0b", "0d", "09", "0e" } };

        string[,] state = new string[4, 4];
        void InversemixColumnsOperation()
        {
            for (int col = 0; col < 4; col++)
            {
                string[,] tempState = new string[4, 1];
                for (int i = 0; i < 4; i++)
                {
                    tempState[i, 0] = state[i, col];
                }

                string[,] tempColMixMatrix = new string[4, 1];

                for (int i = 0; i < 4; i++)
                {
                    for (int z = 0; z < 4; z++)
                    {
                        tempColMixMatrix[z, 0] = invMixColumns[i, z];
                    }
                    string temp = "";
                    for (int j = 0; j < 4; j++)
                    {
                        string ans = mulInverseMixColumn(tempColMixMatrix[j, 0], tempState[j, 0]);
                        ans = Convert.ToString(Convert.ToInt32(ans, 16), 2).PadLeft(8, '0');
                        temp = XOR(temp, ans);
                    }
                    state[i, col] = Convert.ToString(Convert.ToInt32(temp, 2), 16);
                }
            }
        }

        string XOR(string pt1, string pt2)
        {
            if (pt1 == "") return pt2;
            char[] output = new char[8];
            for (int i = 0; i < pt1.Length; i++)
            {
                if (pt1.Substring(i, 1) == pt2.Substring(i, 1)) output[i] = '0';
                else output[i] = '1';
            }
            return new string(output);
        }

        public int[,] AddRoundKey(int[,] plainText, int[,] key)
        {
            int[,] plain_key = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plain_key[j, i] = plainText[j, i] ^ key[j, i];
                }
            }
            return plain_key;
        }

        private int[,] SubBytes(int[,] ptsub, int[,] sbox)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int tens = ptsub[i, j] / 16;
                    int units = ptsub[i, j] - tens * 16;
                    ptsub[i, j] = sbox[tens, units];


                }
            }
            return ptsub;
        }

        private void ShiftRows(ref int[,] state)
        {

            // Shift second row by one position to the left
            int tmp = state[1, 0];
            state[1, 0] = state[1, 1];
            state[1, 1] = state[1, 2];
            state[1, 2] = state[1, 3];
            state[1, 3] = tmp;

            // Shift third row by two positions to the left
            tmp = state[2, 0];
            state[2, 0] = state[2, 2];
            state[2, 2] = tmp;
            tmp = state[2, 1];
            state[2, 1] = state[2, 3];
            state[2, 3] = tmp;

            // Shift fourth row by three positions to the left
            tmp = state[3, 0];
            state[3, 0] = state[3, 3];
            state[3, 3] = state[3, 2];
            state[3, 2] = state[3, 1];
            state[3, 1] = tmp;


        }

        private void ShiftRowsDec(ref int[,] state)
        {

            // Shift second row by one position to the left
            int tmp = state[1, 3];
            state[1, 3] = state[1, 2];
            state[1, 2] = state[1, 1];
            state[1, 1] = state[1, 0];
            state[1, 0] = tmp;



            // Shift third row by two positions to the left
            tmp = state[2, 3];
            state[2, 3] = state[2, 1];
            state[2, 1] = tmp;
            tmp = state[2, 2];
            state[2, 2] = state[2, 0];
            state[2, 0] = tmp;

            // Shift fourth row by three positions to the left
            tmp = state[3, 3];
            state[3, 3] = state[3, 0];
            state[3, 0] = state[3, 1];
            state[3, 1] = state[3, 2];
            state[3, 2] = tmp;

        }


        public override string Decrypt(string cipherText, string key)
        {
            int[,] intKey = new int[4, 4]; int[,] iney = new int[4, 4], resultOfAddRoundKey = new int[4, 4];
            int[,] cipher = new int[4, 4];
            int[,] resultOfSubBytes = new int[4, 4];
            int cnt = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string s = ("0x" + key.Substring(cnt, 2));
                    intKey[j, i] = Convert.ToInt32(s, 16);
                    cnt += 2;
                }
            }
            List<int[,]> keys = new List<int[,]>
            {
                intKey
            };
            iney = KeyScheduleRevese(intKey, 0);
            for (int i = 1; i < 10; i++)
            {
                keys.Add(iney);
                iney = KeyScheduleRevese(iney, i);

            }
            keys.Add(iney);

            cnt = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string s = ("0x" + cipherText.Substring(cnt, 2));
                    resultOfSubBytes[j, i] = Convert.ToInt32(s, 16);
                    cnt += 2;
                }
            }

            for (int i = 10; i >= 1; i--)
            {
                resultOfAddRoundKey = AddRoundKey(resultOfSubBytes, keys[i]);
                string ss = "0x";

                if (i < 10)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            //if (resultOfAddRoundKey[k,j ] < 16)
                            //    state[k, j] += '0';
                            state[k, j] = resultOfAddRoundKey[k, j].ToString("X");
                        }
                    }
                    //resultOfAddRoundKey = MixColunmsReverse(resultOfAddRoundKey, INVmatrixMaxColumns);
                        InversemixColumnsOperation();
                    for (int k = 0; k < state.GetLength(0); k++)
                    {
                        for (int j = 0; j < state.GetLength(1); j++)
                        {
                            resultOfAddRoundKey[k, j] = Convert.ToInt32(state[k, j], 16); ;
                        }
                    }
                    for (int k = 0; k < 4; k++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            if (resultOfAddRoundKey[j, k] < 16)
                                ss += '0';
                            ss += resultOfAddRoundKey[j, k].ToString("X");
                        }
                    }
                }
                ShiftRowsDec(ref resultOfAddRoundKey);

                resultOfSubBytes = SubBytes(resultOfAddRoundKey, inv_sbox);

            }
            resultOfAddRoundKey = AddRoundKey(resultOfSubBytes, keys[0]);
            string plainText = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (resultOfAddRoundKey[j, i] < 16)
                        plainText += '0';
                    plainText += resultOfAddRoundKey[j, i].ToString("X");
                }
            }
            return plainText;
        }


        public override string Encrypt(string plainText, string key)
        {

            string cipherText = "0x";
            int[,] intKey = new int[4, 4], iney = new int[4, 4], plain = new int[4, 4], resultOfAddRoundKey = new int[4, 4];
            int[,] resultOfSubBytes = new int[4, 4];
            int cnt = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    string s = ("0x" + key.Substring(cnt, 2));
                    intKey[j, i] = Convert.ToInt32(s, 16);
                    cnt += 2;
                }
            }
            cnt = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string s = ("0x" + plainText.Substring(cnt, 2));
                    plain[j, i] = Convert.ToInt32(s, 16);
                    cnt += 2;
                }
            }

            resultOfAddRoundKey = AddRoundKey(plain, intKey);
            iney = KeyScheduleRevese(intKey, 0);
            for (int i = 0; i < 10; i++)
            {

                cipherText = "0x";

                resultOfSubBytes = SubBytes(resultOfAddRoundKey, sbox);

                ShiftRows(ref resultOfSubBytes);

                if (i < 9)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            if (resultOfSubBytes[j, k] < 16)
                                cipherText += '0';
                            cipherText += resultOfSubBytes[j, k].ToString("X");
                        }
                    }
                    resultOfSubBytes = MixColunms(resultOfSubBytes, matrixMaxColumns);


                }
                resultOfAddRoundKey = AddRoundKey(resultOfSubBytes, iney);
                if (i < 9)
                    iney = KeyScheduleRevese(iney, i + 1);


            }
            cipherText = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (resultOfAddRoundKey[j, i] < 16)
                        cipherText += '0';
                    cipherText += resultOfAddRoundKey[j, i].ToString("X");
                }
            }
            return cipherText;
        }

    }
}
