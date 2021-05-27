using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {

            int[] a_arr = { 1, 0, baseN };
            int[] b_arr = { 0, 1, number };
            int eq;
            int[] t = { 0, 0, 0 };
            while (b_arr[2] != 0 && b_arr[2] != 1)
            {
                eq = a_arr[2] / b_arr[2];

                for (int j = 0; j < 3; j++)
                {
                    t[j] = a_arr[j] - (eq * b_arr[j]);
                    a_arr[j] = b_arr[j];
                    b_arr[j] = t[j];
                }

            }
            return b_arr[2] == 0 ? -1 : b_arr[1] < -1 ? b_arr[1] + baseN : b_arr[1];

        }
    }
}