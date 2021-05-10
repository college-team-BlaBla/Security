using System.Collections.Generic;


namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public char[,] genArray()
        {
            char[,] arr = new char[26, 26];

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {

                    int let = i + j;

                    if (let >= 26)
                        let = let - 26;

                    let = let + 97;

                    char letter = (char)let;

                    arr[i, j] = letter;

                }
            }

            return arr;
        }
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            char[,] shiftletters = genArray();
            Dictionary<char, int> D = new Dictionary<char, int>();
            int a = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                D[c] = a++;
            }
            string key = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                for (char c = 'a'; c <= 'z'; c++)
                {
                    if (shiftletters[D[plainText[i]], D[c]] == cipherText.ToLower()[i])
                    {
                        key += c;
                    }
                }
            }
            int cv = 1;
            int move = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (move < 5)
                {
                    for (int j = cv; j < key.Length; j++)
                    {
                        if (key[i] == key[j])
                        {
                            cv = j;
                            move++;
                            break;
                        }
                    }
                }
            }
            int keySize = cv - (move - 1);
            string TheKey = "";
            for (int i = 0; i < keySize; i++)
            {
                TheKey += key[i];
            }
            return TheKey;
        }

        public string Decrypt(string cipherText, string key)
        {
            char[,] shiftletters = genArray();
            Dictionary<char, int> D = new Dictionary<char, int>();
            int a = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                D[c] = a;
                a++;
            }
            int autokey = cipherText.Length;
            string NewKey = "";
            for (int i = 0; i < autokey; i++)
            {
                NewKey += key[i % key.Length];
            }
            string PlainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (char c = 'a'; c <= 'z'; c++)
                {
                    if (shiftletters[D[c], D[NewKey[i]]] == cipherText.ToLower()[i])
                    {
                        PlainText += c;
                    }
                }
            }
            return PlainText;
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] shiftletters = genArray();
            Dictionary<char, int> D = new Dictionary<char, int>();
            int a = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                D[c] = a;
                a++;
            }
            int autokey = plainText.Length;
            string NewKey = "";
            for (int i = 0; i < autokey; i++)
            {
                NewKey += key[i % key.Length];
            }
            string CipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                CipherText += shiftletters[D[plainText[i]], D[NewKey[i]]];
            }
            return CipherText;
        }
    }
}