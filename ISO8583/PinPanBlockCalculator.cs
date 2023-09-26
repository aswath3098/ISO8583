using System;
using System.Security.Cryptography;
using System.Text;

namespace ISO
{
    class PinPanBlockCalculator
    {
        public static string CalculatePinBlock(string pin)
        {
            string pinblock = "";
            int len = pin.Length;
            if (len == 4)
            {
                pinblock = "04" + pin;
                pinblock = pinblock.PadRight(16, 'F');
                return pinblock;
            }
            else if (len == 12)
            {
                pinblock = "0C" + pin;
                pinblock = pinblock.PadRight(16, 'F');
                return pinblock;
            }
            return pinblock;
        }

        public static string CalculatePanBlock(string track2Data)
        {
            string panblock = track2Data.Substring(4, 12);
            panblock = panblock.PadLeft(16, '0');
            return panblock;
        }

        public static string CalculatePinPanBlock(string pinblock, string panblock)
        {
            if (pinblock.Length != panblock.Length)
                throw new ArgumentException("Input strings must have the same length.");

            char[] result = new char[pinblock.Length];
            for (int i = 0; i < pinblock.Length; i++)
            {
                int value1 = Convert.ToInt32(pinblock[i].ToString(), 16);
                int value2 = Convert.ToInt32(panblock[i].ToString(), 16);
                int xorResult = value1 ^ value2;
                result[i] = Convert.ToChar(xorResult.ToString("X"));
            }

            return new string(result);
        }

        public static byte[] Encrypt3DES(byte[] data, byte[] key)
        {
            using (TripleDESCryptoServiceProvider desProvider = new TripleDESCryptoServiceProvider())
            {
                // Set the encryption mode and padding
                desProvider.Mode = CipherMode.ECB;
                desProvider.Padding = PaddingMode.None;

                // Set the provided key
                desProvider.Key = key;

                // Create the encryptor
                ICryptoTransform encryptor = desProvider.CreateEncryptor();

                // Encrypt the data
                return encryptor.TransformFinalBlock(data, 0, data.Length);
            }
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            int byteCount = hex.Length / 2;
            byte[] bytes = new byte[byteCount];
            for (int i = 0; i < byteCount; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
        public static string ByteArrayToHexString(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                hex.AppendFormat("{0:X2}", b);
            }
            return hex.ToString();
        }
    }
}
