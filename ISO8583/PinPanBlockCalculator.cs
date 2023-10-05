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
            pinblock = ("0" + len.ToString("X") + pin);
            pinblock = pinblock.PadRight(16, 'F');

            return pinblock;
        }
        public static string CalculatePanBlock(string track2Data)
        {

            // Split the track2Data by '=' to extract the portion before '='

            String clearPinBlock = string.Empty;
            string pan = string.Empty;

            var index = track2Data.IndexOf('=');
            //Console.WriteLine(index);
            if (index < 0)
            {
                index = track2Data.IndexOf('D');
            }
            if (index < 0)
            {
                Console.WriteLine("Track2 not Valid");
                return null;
            }

            pan = track2Data.Substring(0, index);
            //Console.WriteLine(pan);
            pan = pan.PadRight(16, '0');

            string account = pan.Substring(0, pan.Length - 1);
            account = account.Substring(account.Length - 12, 12);
            if (account.Length < 12)
            {
                Console.WriteLine("Account must be equal to greater than 12");
                return null;
            }
            else
            {
                clearPinBlock = account.PadLeft(16, '0');

                return clearPinBlock;
            }


            // Handle invalid track2Data format
            throw new ArgumentException("Invalid track2Data format");
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
