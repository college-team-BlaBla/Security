namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string alphabet = "abcdefghijklmnopqrstuvwxyz";

        public int letterNum(char letter) // O(1)
        {
            return letter - 'a';
        }
        public string Encrypt(string plainText, int key)
        {
            int PTLength = plainText.Length;
            string EMessage = "";  // EMessage ==> our Encrypted Message
            for (int i = 0; i < PTLength; i++) // O(N)
            {
                if (char.IsLetter(plainText[i]))
                {
                    int letterIndx = ((key + letterNum(plainText[i])) % 26);
                    EMessage += char.ToUpper(alphabet[letterIndx]);
                }
                else
                {
                    EMessage += plainText[i];
                }
            }

            return EMessage;

        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int Message_size = cipherText.Length;
            string OMessage = ""; // OMessage ==> Our Original Message
            for (int i = 0; i < Message_size; i++) // O(N)
            {
                if (char.IsLetter(cipherText[i]))
                {
                    int letterIndx = ((letterNum(cipherText[i]) - key) % 26);
                    if (letterIndx < 0) letterIndx += 26;
                    OMessage += alphabet[letterIndx];
                }
                else
                {
                    OMessage += cipherText[i];
                }
            }

            return OMessage;
        }

        public int Analyse(string plainText, string cipherText) // O(1)
        {
            if (plainText.Length != cipherText.Length) return -1;
            int letterPN = letterNum(plainText[0]);
            int letterCN = letterNum(char.ToLower(cipherText[0]));

            return (letterCN - letterPN + 26) % 26;
            /* last line  just math trick to skip this if condition have fun with Modular arithmetic roles if u wondering 
             * https://en.wikipedia.org/wiki/Modular_arithmetic 
             * bye  Kamal Saad ^_^
             * if((letterCN - letterPN) < 0)
                     return (letterCN - letterPN) + 26;
             else
                 return (letterCN - letterPN) % 26;
         */
        }
    }
}
