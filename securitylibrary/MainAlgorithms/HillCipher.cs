using System;
using System.Collections.Generic;


namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        int[,] keymatrix;
        int[] linematrix;
        int[] resultmatrix;
        int[,] ListTomatrix;
        int[,] m2m = new int[2, 2];
        int[,] m3m = new int[3, 3];
        int[,] mx2m = new int[2, 2];
        int[,] transpose = new int[3, 3];


        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int[,] plain = new int[2, plainText.Count / 2];
            int[,] cipher = new int[2, plainText.Count / 2];
            int[,] key = new int[2, 2];
            int c = 0;
            for (int i = 0; i < plainText.Count / 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    if (c == plainText.Count)
                        break;
                    plain[j, i] = plainText[c];
                    c++;
                }
            }
            c = 0;
            for (int i = 0; i < plainText.Count / 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    if (c == plainText.Count)
                        break;
                    cipher[j, i] = cipherText[c];
                    c++;
                }
            }



            for (int i = 0; i < plainText.Count / 2; i++)
            {
                for (int row = 0; row < 2; row++)
                {
                    m2m[row, 0] = plain[row, i];
                }

                for (int j = i + 1; j < plainText.Count / 2; j++)
                {
                    for (int row = 0; row < 2; row++)
                    {
                        m2m[row, 1] = plain[row, j];
                    }
                    if (GCD(26, (int)determinant(m2m, 2) % 26) == 1)
                    {
                        for (int row = 0; row < 2; row++)
                        {
                            mx2m[row, 0] = cipher[row, i];
                            mx2m[row, 1] = cipher[row, j];
                        }
                        int[,] inverse = findInverseMatrix_2x2(m2m);
                        for (int cm = 0; cm < 2; cm++)
                        {
                            for (int gc = 0; gc < 2; gc++)
                            {
                                int temp = 0;
                                for (int k = 0; k < 2; k++)
                                {
                                    temp += mx2m[cm, k] * inverse[k, gc];
                                }
                                key[cm, gc] = temp;
                                key[cm, gc] %= 26;
                            }

                        }
                        break;
                    }

                }
                break;
            }
            List<int> returnkey = new List<int>();
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    returnkey.Add(key[i, j]);
                }
            }

            if (returnkey[0] == 0 && returnkey[1] == 0 && returnkey[2] == 0 && returnkey[3] == 0)
                throw new InvalidAnlysisException();
            return returnkey;
        }

        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int[,] plain = new int[2, plainText.Length / 2];
            int[,] cipher = new int[2, plainText.Length / 2];
            int[,] key = new int[2, 2];
            int c = 0;
            for (int i = 0; i < plainText.Length / 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    if (c == plainText.Length)
                        break;
                    plain[j, i] = plainText[c] - 97;
                    c++;
                }
            }
            c = 0;
            for (int i = 0; i < plainText.Length / 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    if (c == plainText.Length)
                        break;
                    cipher[j, i] = cipherText[c] - 97;
                    c++;
                }
            }



            for (int i = 0; i < plainText.Length / 2; i++)
            {
                for (int row = 0; row < 2; row++)
                {
                    m2m[row, 0] = plain[row, i];
                }

                for (int j = i + 1; j < plainText.Length / 2; j++)
                {
                    for (int row = 0; row < 2; row++)
                    {
                        m2m[row, 1] = plain[row, j];
                    }
                    if (GCD(26, (int)determinant(m2m, 2) % 26) == 1)
                    {
                        for (int row = 0; row < 2; row++)
                        {
                            mx2m[row, 0] = cipher[row, i];
                            mx2m[row, 1] = cipher[row, j];
                        }
                        int[,] inverse = findInverseMatrix_2x2(m2m);
                        for (int cm = 0; cm < 2; cm++)
                        {
                            for (int gc = 0; gc < 2; gc++)
                            {
                                int temp = 0;
                                for (int k = 0; k < 2; k++)
                                {
                                    temp += mx2m[cm, k] * inverse[k, gc];
                                }
                                key[cm, gc] = temp;
                                key[cm, gc] %= 26;
                            }

                        }
                        break;
                    }

                }
                break;
            }
            string returnkey = "";
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    returnkey += (char)(key[i, j] + 97);
                }
            }

            if (key[0, 0] == 0 && key[0, 1] == 0 && key[1, 0] == 0 && key[1, 1] == 0)
                throw new InvalidAnlysisException();
            return returnkey;

        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            formtheListInMatrix(key, Convert.ToInt32(Math.Sqrt(key.Count)));
            if (Convert.ToInt32(Math.Sqrt(key.Count)) == 3)
            {
                findInverseMatrix_3x3();
                findTransposeMatrix();
                keymatrix = transpose;
            }
            else
            {
                findInverseMatrix_2x2();
                keymatrix = m2m;
            }

            return divideinList(cipherText, Convert.ToInt32(Math.Sqrt(key.Count)));

        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            List<int> keylist = new List<int>();
            List<int> cipherTextlist = new List<int>();
            List<int> result = new List<int>();
            string returnResult = "";
            for (int i = 0; i < key.Length; i++)
            {
                keylist.Add(key[i] - 97);
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                cipherTextlist.Add(cipherText[i] - 97);
            }

            formtheListInMatrix(keylist, Convert.ToInt32(Math.Sqrt(keylist.Count)));
            if (Convert.ToInt32(Math.Sqrt(keylist.Count)) == 3)
            {
                findInverseMatrix_3x3();
                findTransposeMatrix();
                keymatrix = transpose;
            }
            else
            {
                findInverseMatrix_2x2();
                keymatrix = m2m;
            }

            result = divideinList(cipherTextlist, Convert.ToInt32(Math.Sqrt(keylist.Count)));
            for (int i = 0; i < result.Count; i++)
            {
                returnResult += (char)(result[i] + 97);
            }
            return returnResult;



        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            keytomatrixList(key, Convert.ToInt32(Math.Sqrt(key.Count)));
            return divideinList(plainText, Convert.ToInt32(Math.Sqrt(key.Count)));
        }

        public string Encrypt(string plainText, string key)
        {
            keytomatrix(key, Convert.ToInt32(Math.Sqrt(key.Length)));
            return divide(plainText, Convert.ToInt32(Math.Sqrt(key.Length)));
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int cm = 0;
            int[,] m3m = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (cm == plain3.Count)
                        break;
                    m3m[j, i] = plain3[cm];
                    cm++;
                }
            }
            cm = 0;
            int[,] mx2m = new int[3, 3];
            int[,] key = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (cm == plain3.Count)
                        break;
                    mx2m[j, i] = cipher3[cm];
                    cm++;
                }
            }
            ListTomatrix = m3m;
            findInverseMatrix_3x3();
            findTransposeMatrix();
            int[,] inverse = transpose;
            for (int i = 0; i < 3; i++)
            {
                for (int c = 0; c < 3; c++)
                {
                    int temp = 0;
                    for (int k = 0; k < 3; k++)
                    {
                        temp += mx2m[i, k] * inverse[k, c];
                    }
                    key[i, c] = temp;
                    key[i, c] %= 26;
                }

            }
            List<int> returnkey = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    returnkey.Add(key[i, j]);
                }
            }
            return returnkey;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            cipher3 = cipher3.ToLower();
            int cm = 0;
            int[,] m3m = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (cm == plain3.Length)
                        break;
                    m3m[j, i] = plain3[cm] - 97;
                    cm++;
                }
            }
            cm = 0;
            int[,] mx2m = new int[3, 3];
            int[,] key = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (cm == cipher3.Length)
                        break;
                    mx2m[j, i] = cipher3[cm] - 97;
                    cm++;
                }
            }
            if (GCD(26, (int)determinant(m3m, 3)) != 1)
                throw new InvalidAnlysisException();
            ListTomatrix = m3m;
            findInverseMatrix_3x3();
            findTransposeMatrix();
            int[,] inverse = transpose;

            for (int i = 0; i < 3; i++)
            {
                for (int c = 0; c < 3; c++)
                {
                    int temp = 0;
                    for (int k = 0; k < 3; k++)
                    {
                        temp += mx2m[i, k] * inverse[k, c];
                    }
                    key[i, c] = temp;
                    key[i, c] %= 26;
                }

            }
            string returnkey = "";
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    returnkey += (char)(key[i, j] + 97);
                }
            }
            return returnkey;
        }


        // encrypt functions string_inputs
        public string divide(string temp, int s)
        {
            string result = "";
            while (temp.Length > s)
            {
                string sub = temp.Substring(0, s);
                temp = temp.Substring(s, temp.Length - sub.Length);
                result += perform(sub);
            }
            if (temp.Length == s)
                result += perform(temp);
            else if (temp.Length < s)
            {
                for (int i = temp.Length; i < s; i++)
                    temp = temp + 'x';
                result += perform(temp);
            }
            return result;
        }
        public string perform(string line)
        {
            string result = "";
            linetomatrix(line);
            linemultiplykey(line.Length);
            for (int i = 0; i < line.Length; i++)
            {
                result += (char)(resultmatrix[i] + 97);
            }
            return result;
        }
        public void keytomatrix(string key, int len)
        {
            keymatrix = new int[len, len];
            int c = 0;
            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < len; j++)
                {
                    keymatrix[i, j] = ((int)key[c]) - 97;
                    c++;
                }
            }
        }
        public void linetomatrix(string line)
        {
            linematrix = new int[line.Length];
            for (int i = 0; i < line.Length; i++)
            {
                linematrix[i] = ((int)line[i]) - 97;
            }
        }
        public void linemultiplykey(int len)
        {
            resultmatrix = new int[len];
            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < len; j++)
                {
                    resultmatrix[i] += keymatrix[i, j] * linematrix[j];
                }
                resultmatrix[i] %= 26;
            }
        }


        // encrypt function list_inputs

        public List<int> divideinList(List<int> plain, int s)
        {
            List<int> result = new List<int>();
            List<int> list = new List<int>();

            while (plain.Count > s)
            {
                List<int> sub = plain.GetRange(0, s);
                plain = plain.GetRange(s, plain.Count - sub.Count);
                list = performinList(sub);
                for (int i = 0; i < list.Count; i++)
                    result.Add(list[i]);
            }
            if (plain.Count == s)
            {
                list = performinList(plain);
                for (int i = 0; i < list.Count; i++)
                    result.Add(list[i]);
            }
            else if (plain.Count < s)
            {
                for (int i = plain.Count; i < s; i++)
                    plain.Add(0);
                list = performinList(plain);
                for (int i = 0; i < list.Count; i++)
                    result.Add(list[i]);
            }
            return result;
        }
        public List<int> performinList(List<int> plain)
        {
            List<int> result = new List<int>();
            linetomatrixinList(plain);
            linemultiplykeyinList(plain.Count);
            for (int i = 0; i < plain.Count; i++)
            {
                result.Add(resultmatrix[i]);
            }
            return result;
        }
        public void linetomatrixinList(List<int> plain)
        {
            linematrix = new int[plain.Count];
            for (int i = 0; i < plain.Count; i++)
            {
                linematrix[i] = plain[i];
            }
        }
        public void linemultiplykeyinList(int len)
        {
            resultmatrix = new int[len];
            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < len; j++)
                {
                    resultmatrix[i] += keymatrix[i, j] * linematrix[j];
                }
                resultmatrix[i] %= 26;
                if (resultmatrix[i] < 0)
                    resultmatrix[i] += 26;
            }
        }
        public void keytomatrixList(List<int> key, int len)
        {
            keymatrix = new int[len, len];
            int c = 0;
            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < len; j++)
                {
                    keymatrix[i, j] = key[c];
                    c++;
                }
            }
        }


        // Decrypt list_input
        public void formtheListInMatrix(List<int> list, int rowcol)
        {
            int counter = 0;
            ListTomatrix = new int[rowcol, rowcol];
            for (int i = 0; i < rowcol; i++)
            {
                for (int j = 0; j < rowcol; j++)
                {
                    ListTomatrix[i, j] = list[counter];
                    counter++;
                }
            }
        }
        public void findInverseMatrix_3x3()
        {
            //find determenant of the matrix
            double det = determinant(ListTomatrix, 3);
            while (det < 0)
                det += 26;
            // find multiplicative inverse
            int b = mul_inv(Convert.ToInt32(det), 26);

            int h = 0, y = 0, counter = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    for (int k = 0; k < 3; k++)
                    {
                        for (int mx = 0; mx < 3; mx++)
                        {
                            if (mx != j && k != i)
                            {
                                m2m[h, y] = ListTomatrix[k, mx];
                                counter++;
                                y++;
                                if (counter == 2)
                                {
                                    h++;
                                    y = 0;
                                }
                            }
                        }
                    }
                    counter = 0;
                    h = 0; y = 0;
                    double sign = Math.Pow(-1, i + j);
                    int value = b * Convert.ToInt32(sign) * Convert.ToInt32(determinant(m2m, 2)) % 26;
                    if (value < 0)
                        value += 26;
                    m3m[i, j] = value;
                }
            }
        }
        public void findTransposeMatrix()
        {
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    transpose[j, i] = m3m[i, j];
                }
            }

        }
        public void findInverseMatrix_2x2()
        {
            m2m[0, 0] = ListTomatrix[1, 1];
            m2m[0, 1] = -1 * ListTomatrix[0, 1];
            m2m[1, 0] = -1 * ListTomatrix[1, 0];
            m2m[1, 1] = ListTomatrix[0, 0];


            //find determenant of the matrix
            double det = determinant(ListTomatrix, 2);
            while (det < 0)
                det += 26;
            int x = mul_inv((int)det, 26);
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    m2m[i, j] = x * m2m[i, j];
                }
            }

        }
        static public int[,] findInverseMatrix_2x2(int[,] m)
        {
            int[,] m2m = new int[2, 2];
            m2m[0, 0] = m[1, 1];
            m2m[0, 1] = -1 * m[0, 1];
            m2m[1, 0] = -1 * m[1, 0];
            m2m[1, 1] = m[0, 0];


            //find determenant of the matrix
            double det = determinant(m, 2) % 26;
            while (det < 0)
                det += 26;
            int x = mul_inv((int)det, 26);

            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    m2m[i, j] = x * m2m[i, j];
                    m2m[i, j] %= 26;

                }

            }
            return m2m;
        }

        static public double determinant(int[,] A, int N)
        {
            double res;
            if (N == 1)
                res = A[0, 0];
            else if (N == 2)
            {
                res = A[0, 0] * A[1, 1] - A[1, 0] * A[0, 1];
            }
            else
            {
                res = 0;
                for (int j1 = 0; j1 < N; j1++)
                {
                    int[,] m = new int[N - 1, N - 1];
                    for (int i = 1; i < N; i++)
                    {
                        int j2 = 0;
                        for (int j = 0; j < N; j++)
                        {
                            if (j == j1)
                                continue;
                            m[i - 1, j2] = A[i, j];
                            j2++;
                        }
                    }
                    res += Math.Pow(-1.0, 1.0 + j1 + 1.0) * A[0, j1] * determinant(m, N - 1);
                }
            }
            return res;
        }
        static public int mul_inv(int A3, int B3)
        {
            int Base = B3, t, Q;
            int A2 = 0, B2 = 1;
            if (B3 == 1) return 1;
            while (A3 > 1)
            {
                Q = A3 / B3;
                t = B3;
                B3 = A3 % B3;
                A3 = t;
                t = A2;
                A2 = B2 - Q * A2;
                B2 = t;
            }
            if (B2 < 0) B2 += Base;
            return B2;
        }


        //analysis
        public int GCD(int p, int q)
        {
            if (q == 0)
            {
                return p;
            }

            int r = p % q;

            return GCD(q, r);
        }

    }
}