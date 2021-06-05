using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace IPTables.Net.Iptables.Helpers
{
    public class ShortHash
    {
        private static string ConvertHexStringToBase64(string hexString)
        {
            var buffer = new byte[hexString.Length / 2];
            for (var i = 0; i < hexString.Length; i++)
            {
                buffer[i / 2] = Convert.ToByte(Convert.ToInt32(hexString.Substring(i, 2), 16));
                i += 1;
            }

            var res = Convert.ToBase64String(buffer);
            return res;
        }

        public static string HexHash(string inputString)
        {
            HashAlgorithm algorithm = MD5.Create(); //or use SHA1.Create();
            var sb = new StringBuilder();
            var bytes = algorithm.ComputeHash(Encoding.UTF8.GetBytes(inputString));
            foreach (var b in bytes)
                sb.Append(b.ToString("X2"));
            var b64 = ConvertHexStringToBase64(sb.ToString()).Substring(2);

            return b64.TrimEnd(new char[] {'='});
        }
    }
}