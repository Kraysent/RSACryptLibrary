using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace RSACryptLibrary.src
{
    class Options
    {
        public const char EncryptionSplitChar = ' ';
        public const string EncryptionDelimiter = "987";

        /// <summary>
        /// Computes hash using SHA256 hash algorythm
        /// </summary>
        /// <param name="text"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static byte[] ComputeHash(string text)
        {
            SHA256 hash = new SHA256Managed();

            return hash.ComputeHash(ToByteArray(text));
        }
        
        /// <summary>
        /// Computes hash using SHA256 hash algorythm
        /// </summary>
        /// <param name="text"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static byte[] ComputeHash(byte[] byteArray)
        {
            SHA256 hash = new SHA256Managed();

            return hash.ComputeHash(byteArray);
        }

        /// <summary>
        /// Computes hash using SHA256 hash algorythm
        /// </summary>
        /// <param name="text"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static byte[] ComputeHash(string text, SHA256 hash)
        {
            hash = new SHA256Managed();

            return hash.ComputeHash(ToByteArray(text));
        }

        /// <summary>
        /// Computes hash using SHA256 hash algorythm
        /// </summary>
        /// <param name="text"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static byte[] ComputeHash(byte[] byteArray, SHA256 hash)
        {
            hash = new SHA256Managed();

            return hash.ComputeHash(byteArray);
        }

        /// <summary>
        /// Computes hash using SHA512 hash algorythm
        /// </summary>
        /// <param name="text"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static byte[] ComputeHash(string text, SHA512 hash)
        {
            hash = new SHA512Managed();

            return hash.ComputeHash(ToByteArray(text));
        }

        /// <summary>
        /// Computes hash using SHA512 hash algorythm
        /// </summary>
        /// <param name="text"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static byte[] ComputeHash(byte[] byteArray, SHA512 hash)
        {
            hash = new SHA512Managed();

            return hash.ComputeHash(byteArray);
        }
        
        /// <summary>
        /// Computes hash using MD5 hash algorythm
        /// </summary>
        /// <param name="text"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static byte[] ComputeHash(string text, MD5 hash)
        {
            hash = new MD5CryptoServiceProvider();

            return hash.ComputeHash(ToByteArray(text));
        }

        /// <summary>
        /// Computes hash using MD5 hash algorythm
        /// </summary>
        /// <param name="text"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static byte[] ComputeHash(byte[] byteArray, MD5 hash)
        {
            hash = new MD5CryptoServiceProvider();

            return hash.ComputeHash(byteArray);
        }

        /// <summary>
        /// Converts text to byte array
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        public static byte[] ToByteArray(string text)
        {
            return Encoding.Unicode.GetBytes(text);
        }

        /// <summary>
        /// Converts byte array to text
        /// </summary>
        /// <param name="byteArray"></param>
        /// <returns></returns>
        public static string ToText(byte[] byteArray)
        {
            return Encoding.Unicode.GetString(byteArray);
        }
    }
}
