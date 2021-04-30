﻿using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public struct KOMatrices
    {
        public Dictionary<char, Tuple<int, int>> KM;
        public List<List<char>> OM;
    }

    public class PlayFair : ICryptographicTechnique<string, string>
    {
        public HashSet<char> ModifiedKey(string key)
        {
            string alphabet = "abcdefghiklmnopqrstuvwxyz"; // j removed
            HashSet<char> Mkey = new HashSet<char>();
            int keyLength = key.Length;
            for (int i = 0; i < keyLength; i++)
            {
                if (key[i] == 'j')
                {
                    Mkey.Add('i');
                }
                else
                {
                    Mkey.Add(key[i]);
                }
            }

            for (int i = 0; i < 25; i++)
            {
                Mkey.Add(alphabet[i]); // j not exist!
            }

            return Mkey;

        }

        public KOMatrices KOFunc(HashSet<char> Mkey)
        {
            Dictionary<char, Tuple<int, int>> KMatrix = new Dictionary<char, Tuple<int, int>>();
            List<List<char>> OMatrix = new List<List<char>>();
            int counter = 0;
            for (int i = 0; i < 5; i++)
            {
                List<char> tmp = new List<char>();
                for (int j = 0; j < 5; j++)
                {

                    KMatrix.Add(Mkey.ElementAt(counter), new Tuple<int, int>(i, j));
                    tmp.Add(Mkey.ElementAt(counter));
                    counter++;

                }

                OMatrix.Add(tmp);
            }

            KOMatrices komatrix = new KOMatrices();
            komatrix.KM = KMatrix;
            komatrix.OM = OMatrix;

            return komatrix;
        }



        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            List<string> smallSegs = new List<string>();


            KOMatrices matrix = KOFunc(ModifiedKey(key));
            string FPT = "";

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char c1 = cipherText[i], c2 = cipherText[i + 1];
                if (matrix.KM[c1].Item2 == matrix.KM[c2].Item2)
                {
                    FPT += matrix.OM[(matrix.KM[c1].Item1 + 4) % 5][matrix.KM[c1].Item2];
                    FPT += matrix.OM[(matrix.KM[c2].Item1 + 4) % 5][matrix.KM[c2].Item2];
                }
                else if (matrix.KM[c1].Item1 == matrix.KM[c2].Item1)
                {
                    FPT += matrix.OM[matrix.KM[c1].Item1][(matrix.KM[c1].Item2 + 4) % 5];
                    FPT += matrix.OM[matrix.KM[c2].Item1][(matrix.KM[c2].Item2 + 4) % 5];
                }
                else
                {
                    FPT += matrix.OM[matrix.KM[c1].Item1][matrix.KM[c2].Item2];
                    FPT += matrix.OM[matrix.KM[c2].Item1][matrix.KM[c1].Item2];
                }

            }


            string ans = FPT;
            if (FPT[FPT.Length - 1] == 'x')
            {
                ans = ans.Remove(FPT.Length - 1);
            }

            int w = 0;
            for (int i = 0; i < ans.Length; i++)
            {
                if (FPT[i] == 'x')
                {
                    if (FPT[i - 1] == FPT[i + 1])
                    {
                        if (i + w < ans.Length && (i - 1) % 2 == 0)
                        {
                            ans = ans.Remove(i + w, 1);
                            w--;
                        }
                    }
                }
            }

            FPT = ans;
            Console.WriteLine(FPT);
            return FPT;
        }


        public string Encrypt(string plainText, string key)
        {
            string CT = "";

            KOMatrices KOkey = KOFunc(ModifiedKey(key));
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Substring(0, i + 1) + 'x' + plainText.Substring(i + 1);
                }

            }
            if (plainText.Length % 2 == 1) plainText += 'x';
            int PTLength = plainText.Length;
            for (int i = 0; i < PTLength; i += 2)
            {
                char c1 = plainText[i], c2 = plainText[i + 1];
                if (KOkey.KM[c1].Item2 == KOkey.KM[c2].Item2) //same column
                {
                    CT += KOkey.OM[(KOkey.KM[c1].Item1 + 1) % 5][KOkey.KM[c1].Item2];
                    CT += KOkey.OM[(KOkey.KM[c2].Item1 + 1) % 5][KOkey.KM[c2].Item2];
                }
                else if (KOkey.KM[c1].Item1 == KOkey.KM[c2].Item1)//same row
                {
                    CT += KOkey.OM[KOkey.KM[c1].Item1][(KOkey.KM[c1].Item2 + 1) % 5];
                    CT += KOkey.OM[KOkey.KM[c2].Item1][(KOkey.KM[c2].Item2 + 1) % 5];
                }
                else
                {
                    CT += KOkey.OM[KOkey.KM[c1].Item1][KOkey.KM[c2].Item2];
                    CT += KOkey.OM[KOkey.KM[c2].Item1][KOkey.KM[c1].Item2];
                }
            }

            return CT.ToUpper();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
    }
}