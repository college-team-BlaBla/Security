using System;
using System.Collections.Generic;


namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            List<string> railFence = new List<string>();
            int key = 2;
            while (key >= 2)
            {
                double len = Math.Ceiling((plainText.Length / double.Parse(key.ToString())));
                int n = int.Parse(len.ToString());
                string[,] ch = new string[n, key];
                int c = 0;
                int lenkey = int.Parse(key.ToString());
                int diffletters = (n * lenkey) - plainText.Length;
                while (diffletters > 0)
                {
                    plainText += " ";
                    diffletters--;
                }
                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < lenkey; j++)
                    {
                        ch[i, j] = plainText[c].ToString();
                        c++;
                    }
                }
                string check = "";
                for (int i = 0; i < lenkey; i++)
                {

                    for (int j = 0; j < n; j++)
                    {
                        if (ch[j, i] == " ")
                        {
                            continue;
                        }
                        check += ch[j, i];
                    }
                }
                string final = "";
                for (int i = 0; i < cipherText.Length; i++)
                {
                    if (cipherText.ToLower()[i] == 'x') continue;
                    final += cipherText.ToLower()[i].ToString();
                }
                if (check == final) break;
                key++;
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            double len = Math.Ceiling((cipherText.Length / double.Parse(key.ToString())));
            int n = int.Parse(len.ToString());
            int lenkey = int.Parse(key.ToString());
            string[,] ch = new string[lenkey, n];
            int c = 0;
            int diffletters = (n * lenkey) - cipherText.Length;
            while (diffletters > 0)
            {
                cipherText += " ";
                diffletters--;
            }
            for (int i = 0; i < lenkey; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    ch[i, j] = cipherText.ToLower()[c].ToString();
                    c++;
                }
            }
            string PlaintText = "";
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < lenkey; j++)
                {
                    if (ch[j, i] == " ") continue;
                    PlaintText += ch[j, i];
                }
            }
            return PlaintText;
        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            double len = Math.Ceiling((plainText.Length / double.Parse(key.ToString())));
            int n = int.Parse(len.ToString());
            string[,] ch = new string[n, key];
            int c = 0;
            int lenkey = int.Parse(key.ToString());
            int diffletters = (n * lenkey) - plainText.Length;
            while (diffletters > 0)
            {
                plainText += " ";
                diffletters--;
            }
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < lenkey; j++)
                {
                    ch[i, j] = plainText[c].ToString();
                    c++;
                }
            }
            string CipherText = "";
            for (int i = 0; i < lenkey; i++)
            {

                for (int j = 0; j < n; j++)
                {
                    if (ch[j, i] == " ")
                    {
                        continue;
                    }
                    CipherText += ch[j, i];
                }
            }
            return CipherText.ToUpper();
        }
    }
}