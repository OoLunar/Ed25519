using System.Linq;
using System.Numerics;

namespace Cryptographic
{
    /*
     * Refactored from netframework v4 to net5.0 by lunar@forsaken-borders.net <Lunar Starstrum>, August 10th, 2023
     * Released to the public domain

     * Ported and refactored from Java to C# by Hans Wolff, 10/10/2013
     * Released to the public domain

     * Java code written by k3d3
     * Source: https://github.com/k3d3/ed25519-java/blob/master/ed25519.java
     * Released to the public domain
     */

    /// <summary>
    /// Provides cryptographic operations using the Ed25519 elliptic curve algorithm.
    /// </summary>
    /// <remarks>
    /// This partial class provides a collection of cryptographic operations using the Ed25519 elliptic curve
    /// algorithm. The operations include key generation, signature creation, signature validation, and more.
    ///
    /// The class contains methods for key generation, signature creation, signature validation, and various
    /// helper functions used in the Ed25519 algorithm. The Ed25519 algorithm combines elliptic curve cryptography
    /// with hashing to achieve digital signatures with high security.
    /// </remarks>
    public static partial class Ed25519
    {
        /// <summary>
        /// Represents the length of the Ed25519 field in bits.
        /// </summary>
        private const int BIT_LENGTH = 256;

        /// <summary>
        /// Represents a constant value: 2^(BIT_LENGTH - 2).
        /// Used in various calculations within the Ed25519 implementation.
        /// </summary>
        private static readonly BigInteger _twoPowBitLengthMinusTwo = BigInteger.Pow(2, BIT_LENGTH - 2);

        /// <summary>
        /// Precomputed values of 2 raised to various powers, from 0 to 2 * BIT_LENGTH.
        /// Used for optimizations in the Ed25519 algorithm.
        /// </summary>
        private static readonly BigInteger[] _powerOfTwoCache = Enumerable.Range(0, 2 * BIT_LENGTH).Select(i => BigInteger.Pow(2, i)).ToArray();

        /// <summary>
        /// Prime modulus q used in modular arithmetic operations.
        /// </summary>
        private static readonly BigInteger _q = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564819949");

        /// <summary>
        /// Value q - 2, used in certain calculations within the Ed25519 implementation.
        /// </summary>
        private static readonly BigInteger _qm2 = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564819947");

        /// <summary>
        /// Value q + 3, used in certain calculations within the Ed25519 implementation.
        /// </summary>
        private static readonly BigInteger _qp3 = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564819952");

        /// <summary>
        /// Prime order l used to define a subgroup of the Ed25519 curve.
        /// </summary>
        private static readonly BigInteger _l = BigInteger.Parse("7237005577332262213973186563042994240857116359379907606001950938285454250989");

        /// <summary>
        /// Constant d used in the formula for scalar multiplication of the base point of the Ed25519 curve.
        /// </summary>
        private static readonly BigInteger _d = BigInteger.Parse("-4513249062541557337682894930092624173785641285191125241628941591882900924598840740");

        /// <summary>
        /// Constant i used in the Ed25519 algorithm.
        /// </summary>
        private static readonly BigInteger _i = BigInteger.Parse("19681161376707505956807079304988542015446066515923890162744021073123829784752");

        /// <summary>
        /// Y-coordinate of the base point multiplied by the cofactor of the Ed25519 curve.
        /// </summary>
        private static readonly BigInteger _by = BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960");

        /// <summary>
        /// X-coordinate of the base point of the Ed25519 curve.
        /// </summary>
        private static readonly BigInteger _bx = BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202");

        /// <summary>
        /// Reduced (x, y) coordinates of the base point modulo q, used as a starting point for computations.
        /// </summary>
        private static readonly (BigInteger, BigInteger) _b = new(_bx.Mod(_q), _by.Mod(_q));

        /// <summary>
        /// Value 2^256 - 38 used in scalar multiplication calculations.
        /// </summary>
        private static readonly BigInteger _un = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564819967");

        /// <summary>
        /// Value 2 used in various calculations.
        /// </summary>
        private static readonly BigInteger _two = new(2);

        /// <summary>
        /// Value 8 used in certain bitwise operations.
        /// </summary>
        private static readonly BigInteger _eight = new(8);
    }
}
