using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string alphabet = "abcdefghijklmnopqrstuvwxyz";

        public int letterNum(char letter) // O(1)
        {
            return letter - 'a';
        }

        public Dictionary<char, char> KeyDictionary(string key, string Operation)// O(1)
        {
            Dictionary<char, char> dic = new Dictionary<char, char>(); //  dictionary to safe key , letter 
            for (int i = 0; i < 26; i++)
            {
                if (Operation == "encrypt")
                    dic.Add(alphabet[i], key[i]);
                else
                    dic.Add(key[i], alphabet[i]);
            }
            return dic;
        }
        public string Analyse(string plainText, string cipherText) // O()
        {
            SortedDictionary<char, char> KeyTable = new SortedDictionary<char, char>();
            bool[] visted_arr = new bool[30];

            for (int i = 0; i < 30; i++)// O(1)
                visted_arr[i] = false;

            int PTLength = plainText.Length;
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            for (int i = 0; i < PTLength; i++) // O(N)
            {
                if (!KeyTable.ContainsKey(plainText[i]))
                {
                    KeyTable.Add(plainText[i], cipherText[i]);
                    visted_arr[letterNum(cipherText[i])] = true;
                }
            }
            if (KeyTable.Count != 26) //O(1)
            {

                for (int i = 0; i < 26; i++)
                {
                    if (!KeyTable.ContainsKey(alphabet[i]))
                    {
                        for (int j = 0; j < 26; j++)
                        {
                            if (!visted_arr[letterNum(alphabet[j])])
                            {
                                KeyTable.Add(alphabet[i], alphabet[j]);
                                visted_arr[letterNum(alphabet[j])] = true;

                                break;
                            }
                        }
                    }
                }
            }

            string key = "";
            foreach (var item in KeyTable) // O(1)
            {
                key += item.Value;
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            Dictionary<char, char> keyTable = KeyDictionary(key, "decrypt");
            cipherText = cipherText.ToLower();
            int CTLength = cipherText.Length;
            string PT = "";
            for (int i = 0; i < CTLength; i++) // O(N)
            {
                if (char.IsLetter(cipherText[i]))
                    PT += keyTable[cipherText[i]];
                else
                    PT += cipherText[i];
            }
            return PT;

        }

        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, char> keyTable = KeyDictionary(key, "encrypt");
            int PTLength = plainText.Length;
            string CT = "";
            for (int i = 0; i < PTLength; i++) //O(N)
            {
                if (char.IsLetter(plainText[i]))
                    CT += keyTable[plainText[i]];
                else
                    CT += plainText[i];
            }

            return CT.ToUpper();
        }

        /// <summary>
        /// Frequency Information: ETAOINSRHLDCUMFPGWYBVKXJQZ

        public string AnalyseUsingCharFrequency(string cipher)
        {
            string alphabetFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            Dictionary<char, int> CAlphaFreq = new Dictionary<char, int>();
            SortedDictionary<char, char> keyTable = new SortedDictionary<char, char>();
            cipher = cipher.ToLower();
            int CTLength = cipher.Length;
            string key = "";
            for (int i = 0; i < CTLength; i++)
            {
                if (!CAlphaFreq.ContainsKey(cipher[i]))
                {
                    CAlphaFreq.Add(cipher[i], 0);
                }
                else
                {
                    CAlphaFreq[cipher[i]]++;
                }
            }

            CAlphaFreq = CAlphaFreq.OrderBy(x => x.Value).Reverse().ToDictionary(x => x.Key, x => x.Value);
            int counter = 0;
            foreach (var item in CAlphaFreq)
            {
                keyTable.Add(item.Key, alphabetFreq[counter]);
                counter++;
            }

            for (int i = 0; i < CTLength; i++)
            {
                key += keyTable[cipher[i]];
            }

            return key;
        }
    }
}