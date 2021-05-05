using System;
using System.Collections.Generic;


namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            int lenPlain = plainText.Length;
            int lenCipher = plainText.Length;
            List<string> plain = new List<string>();
            List<string> Cipher = new List<string>();
            List<int> TheKey = new List<int>();
            int key = 2;
            while (key >= 2)
            {
                int LenPT = int.Parse(Math.Ceiling((lenPlain / double.Parse(key.ToString()))).ToString());
                int LenCT = int.Parse(Math.Ceiling((lenCipher / double.Parse(key.ToString()))).ToString());
                string[,] plainMat = new string[LenPT, key];
                string[,] CipherMat = new string[LenCT, key];
                int diff = (key * LenPT) - lenPlain;
                while (diff > 0)
                {
                    plainText += " ";
                    diff--;
                }
                int k = 0;
                for (int i = 0; i < LenPT; i++)
                {
                    for (int j = 0; j < key; j++)
                    {
                        plainMat[i, j] = plainText[k].ToString();
                        k++;
                    }
                }
                ///////////////////////////////////////////
                for (int i = 0; i < key; i++)
                {
                    string ss = "";
                    for (int j = 0; j < LenPT; j++)
                    {
                        if (plainMat[j, i] == " ") continue;
                        ss += plainMat[j, i];
                    }
                    plain.Add(ss);
                }
                ///////////////////////cipher///////////////////
                int dif = (key * LenCT) - lenCipher;
                for (int i = LenCT - 1; i >= 0; i--)
                {
                    for (int j = key - 1; j >= 0; j--)
                    {
                        if (dif > 0)
                        {
                            CipherMat[i, j] = " ";
                            dif--;
                        }
                        else
                        {
                            CipherMat[i, j] = "x";
                        }
                    }
                }
                int ii = 0;
                for (int i = 0; i < key; i++)
                {
                    for (int j = 0; j < LenCT; j++)
                    {
                        if (CipherMat[j, i] == " ") { continue; }
                        else
                        {
                            CipherMat[j, i] = cipherText.ToLower()[ii].ToString();
                            ii++;
                        }
                    }
                }
                for (int i = 0; i < key; i++)
                {
                    string ss = "";
                    for (int j = 0; j < LenCT; j++)
                    {
                        if (CipherMat[j, i] == " ") continue;
                        ss += CipherMat[j, i];
                    }
                    Cipher.Add(ss);
                }
                /////////////////////test////////////////

                for (int t = 0; t < plain.Count; t++)
                {
                    for (int d = 0; d < Cipher.Count; d++)
                    {
                        if (plain[t] == Cipher[d])
                        {
                            TheKey.Add(d + 1);
                        }
                    }
                }
                if (TheKey.Count > 1) break;
                key++;
                TheKey.Clear();
                Cipher.Clear();
                plain.Clear();
                /////////////////////////////////////////
            }
            return TheKey;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            int CipherSize = cipherText.Length;
            int KeySize = key.Count;
            int Len = int.Parse(Math.Ceiling((CipherSize / double.Parse(KeySize.ToString()))).ToString());
            int diff = (KeySize * Len) - CipherSize;
            string[,] ch = new string[Len, KeySize];
            for (int i = Len - 1; i >= 0; i--)
            {
                for (int j = KeySize - 1; j >= 0; j--)
                {
                    if (diff > 0)
                    {
                        ch[i, j] = " ";
                        diff--;
                    }
                    else
                    {
                        ch[i, j] = "x";
                    }
                }
            }
            List<int> index = new List<int>();
            for (int i = 1; i <= KeySize; i++)
            {
                for (int j = 0; j < KeySize; j++)
                {
                    if (key[j] == i)
                    {
                        index.Add(j);
                        break;
                    }
                }
            }
            int ii = 0;
            for (int i = 0; i < index.Count; i++)
            {
                for (int j = 0; j < Len; j++)
                {
                    if (ch[j, index[i]] == " ") { continue; }
                    else
                    {
                        ch[j, index[i]] = cipherText.ToLower()[ii].ToString();
                        ii++;
                    }
                }
            }
            string PlaintText = "";
            for (int i = 0; i < Len; i++)
            {
                for (int j = 0; j < index.Count; j++)
                {
                    if (ch[i, j] == " ") continue;
                    PlaintText += ch[i, j];
                }
            }
            return PlaintText;

        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            int PlainSize = plainText.Length;
            int KeySize = key.Count;
            int Len = int.Parse(Math.Ceiling((PlainSize / double.Parse(KeySize.ToString()))).ToString());
            string[,] ch = new string[Len, KeySize];
            List<string> value = new List<string>();
            Dictionary<string, int> Mp = new Dictionary<string, int>();
            int diff = (KeySize * Len) - PlainSize;
            while (diff > 0)
            {
                plainText += " ";
                diff--;
            }
            int k = 0;
            for (int i = 0; i < Len; i++)
            {
                for (int j = 0; j < KeySize; j++)
                {
                    ch[i, j] = plainText[k].ToString();
                    k++;
                }
            }
            for (int i = 0; i < KeySize; i++)
            {
                string ss = "";
                for (int j = 0; j < Len; j++)
                {
                    if (ch[j, i] == " ") continue;
                    ss += ch[j, i];
                }
                value.Add(ss);
            }
            for (int i = 0; i < key.Count; i++)
            {
                Mp[value[i]] = key[i] - 1;
            }
            string CipherText = "";
            for (int i = 0; i < key.Count; i++)
            {
                foreach (KeyValuePair<string, int> pair in Mp)
                {
                    if (pair.Value == i)
                    {
                        CipherText += pair.Key;
                        break;
                    }
                }
            }
            return CipherText.ToUpper();
        }
    }
}