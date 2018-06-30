using System;

namespace RSACryptLibrary
{
    class KeyTypeIsWrongException : Exception
    {
        public KeyTypeIsWrongException(string message) : base(message)
        {

        }
    }
}
