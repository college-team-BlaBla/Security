using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public char[,] genArray()
        {
            char[,] arr = new char[26, 26];

            // Two for loops to generate the grid
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {

                    // Creates an int that will later be cast to a char
                    int let = i + j;

                    // Keeps the int from getting too big
                    if (let >= 26)
                        let = let - 26;

                    // Add 65 to the int so that the char will return letters and not ASCII symbols
                    let = let + 97;

                    // Cast the int to a char
                    char letter = (char)let;

                    // Put the char into its respective place in the array
                    arr[i, j] = letter;
                }
            }
            // Returns the grid
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
            int cv = 0;
            int move = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (move < 5)
                {
                    for (int j = cv; j < key.Length; j++)
                    {
                        if (plainText[i] == key[j])
                        {
                            cv = j;
                            move++;
                            break;
                        }
                    }
                }
            }
            int keySize = cv - (move - 1);
            string thekey = "";
            for (int i = 0; i < keySize; i++)
            {
                thekey += key[i];
            }
            return thekey;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            char[,] shiftletters = genArray();
            Dictionary<char, int> D = new Dictionary<char, int>();
            int a = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                D[c] = a++;
            }
            string PlaintText = "";
            string keyStream = key;
            int i = 0;
            while (key.Length < cipherText.Length)
            {
                for (char c = 'a'; c <= 'z'; c++)
                {
                    if (shiftletters[D[c], D[key[i]]] == cipherText.ToLower()[i])
                    {
                        PlaintText += c;
                        keyStream += c;
                    }
                }
                i++;
                key = keyStream;
            }
            PlaintText = "";
            for (int k = 0; k < cipherText.Length; k++)
            {
                for (char c = 'a'; c <= 'z'; c++)
                {
                    if (shiftletters[D[c], D[key[k]]] == cipherText.ToLower()[k])
                    {
                        PlaintText += c;
                    }
                }
            }
            return PlaintText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            char[,] shiftletters = genArray();
            Dictionary<char, int> D = new Dictionary<char, int>();
            int a = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                D[c] = a++;
            }
            int autokey = plainText.Length - key.Length;
            for (int i = 0; i < autokey; i++)
            {
                key += plainText[i];
            }
            string CipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                CipherText += shiftletters[D[plainText[i]], D[key[i]]];
            }
            return CipherText;
        }
    }
}