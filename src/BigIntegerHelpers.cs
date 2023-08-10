using System.Numerics;

namespace System.Security.Cryptography
{
    internal static class BigIntegerHelpers
    {
        public static BigInteger Mod(this BigInteger num, BigInteger modulo)
        {
            BigInteger result = BigInteger.Remainder(num, modulo);
            return result < 0
                ? result + modulo
                : result;
        }
    }
}
