using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;

namespace Cryptographic
{
    public static partial class Ed25519
    {
        /// <summary>
        /// Computes the modular inverse of a given BigInteger with respect to a specific prime modulus.
        /// </summary>
        /// <param name="x">The BigInteger for which the modular inverse will be computed.</param>
        /// <remarks>
        /// This function calculates the modular inverse of the provided BigInteger 'x' with respect to
        /// a specific prime modulus '_q'. In the context of the Ed25519 algorithm, this operation is used
        /// for cryptographic operations involving modular arithmetic.
        ///
        /// The modular inverse of 'x' is computed using the BigInteger.ModPow method, where the exponent
        /// is '_qm2', and the result is taken modulo the prime modulus '_q'.
        /// </remarks>
        /// <returns>The modular inverse of the input BigInteger.</returns>
        private static BigInteger Inv(BigInteger x) => BigInteger.ModPow(x, _qm2, _q);

        /// <summary>
        /// Recovers the x-coordinate of a point on the Ed25519 elliptic curve given its y-coordinate.
        /// </summary>
        /// <param name="y">The y-coordinate of the point on the curve.</param>
        /// <remarks>
        /// This function is used to recover the x-coordinate of a point on the Ed25519 elliptic curve
        /// based on its given y-coordinate. The Ed25519 elliptic curve is defined by a specific prime
        /// modulus '_q' and other parameters like '_d', '_eight', and '_i'.
        ///
        /// The function follows a sequence of calculations that involve modular arithmetic and the
        /// computation of the modular inverse. It computes 'x' using the y-coordinate, ensuring that
        /// it satisfies the curve equation. The result is then adjusted to fulfill certain conditions.
        /// </remarks>
        /// <returns>The computed x-coordinate of the point on the curve.</returns>
        private static BigInteger RecoverX(BigInteger y)
        {
            BigInteger y2 = y * y;
            BigInteger xx = (y2 - BigInteger.One) * Inv((_d * y2) + BigInteger.One);
            BigInteger x = BigInteger.ModPow(xx, _qp3 / _eight, _q);

            // Check if the calculated x satisfies the curve equation, adjust if necessary.
            if (((x * x) - xx).Mod(_q) != BigInteger.Zero)
            {
                x = (x * _i).Mod(_q);
            }

            // Ensure that the x-coordinate is even.
            if (!x.IsEven)
            {
                x = _q - x;
            }

            return x;
        }

        /// <summary>
        /// Performs the Edwards curve arithmetic operation of addition for two points on the curve.
        /// </summary>
        /// <param name="px">The x-coordinate of the first point.</param>
        /// <param name="py">The y-coordinate of the first point.</param>
        /// <param name="qx">The x-coordinate of the second point.</param>
        /// <param name="qy">The y-coordinate of the second point.</param>
        /// <remarks>
        /// This function performs the addition operation on two points (px, py) and (qx, qy) defined on
        /// the Edwards curve. The Edwards curve arithmetic is a fundamental operation in the Ed25519
        /// elliptic curve cryptography.
        ///
        /// The function computes the new coordinates (x3, y3) of the resulting point using modular
        /// arithmetic and the inverse computation. The coordinates are adjusted to be within the curve's
        /// modulus '_q'.
        /// </remarks>
        /// <returns>The resulting (x, y) coordinates of the sum point on the curve.</returns>
        private static (BigInteger, BigInteger) Edwards(BigInteger px, BigInteger py, BigInteger qx, BigInteger qy)
        {
            BigInteger xx12 = px * qx;
            BigInteger yy12 = py * qy;
            BigInteger dtemp = _d * xx12 * yy12;
            BigInteger x3 = ((px * qy) + (qx * py)) * Inv(BigInteger.One + dtemp);
            BigInteger y3 = ((py * qy) + xx12) * Inv(BigInteger.One - dtemp);

            // Ensure that the resulting coordinates are within the curve's modulus '_q'.
            return (x3.Mod(_q), y3.Mod(_q));
        }

        /// <summary>
        /// Performs the Edwards curve arithmetic operation of squaring a point on the curve.
        /// </summary>
        /// <param name="x">The x-coordinate of the point to be squared.</param>
        /// <param name="y">The y-coordinate of the point to be squared.</param>
        /// <remarks>
        /// This function performs the squaring operation on a point (x, y) defined on the Edwards curve.
        /// The Edwards curve arithmetic is a fundamental operation in the Ed25519 elliptic curve cryptography.
        ///
        /// The function computes the new coordinates (x3, y3) of the squared point using modular arithmetic
        /// and the inverse computation. The coordinates are adjusted to be within the curve's modulus '_q'.
        /// </remarks>
        /// <returns>The resulting (x, y) coordinates of the squared point on the curve.</returns>
        private static (BigInteger, BigInteger) EdwardsSquare(BigInteger x, BigInteger y)
        {
            BigInteger xx = x * x;
            BigInteger yy = y * y;
            BigInteger dtemp = _d * xx * yy;
            BigInteger x3 = 2 * x * y * Inv(BigInteger.One + dtemp);
            BigInteger y3 = (yy + xx) * Inv(BigInteger.One - dtemp);

            // Ensure that the resulting coordinates are within the curve's modulus '_q'.
            return (x3.Mod(_q), y3.Mod(_q));
        }

        /// <summary>
        /// Performs scalar multiplication of a point on the Edwards curve with a BigInteger scalar.
        /// </summary>
        /// <param name="p">The (x, y) coordinates of the base point.</param>
        /// <param name="e">The scalar value by which to multiply the base point.</param>
        /// <remarks>
        /// This function performs scalar multiplication of a point (x, y) defined on the Edwards curve
        /// with a given BigInteger scalar 'e'. Scalar multiplication is a key operation in elliptic curve
        /// cryptography and is used extensively in the Ed25519 algorithm.
        ///
        /// The function uses a recursive approach to perform the scalar multiplication efficiently. It
        /// repeatedly divides the scalar 'e' by two, performing Edwards square operations in each step,
        /// and potentially mixing in the base point 'p' using the Edwards addition operation.
        ///
        /// The result is a point (x, y) representing the scaled point on the curve. If the scalar 'e' is
        /// zero, the result is the identity point (0, 1) on the curve.
        /// </remarks>
        /// <returns>The resulting (x, y) coordinates of the scaled point on the curve.</returns>
        private static (BigInteger, BigInteger) ScalarMul((BigInteger, BigInteger) p, BigInteger e)
        {
            if (e == BigInteger.Zero)
            {
                // Identity point
                return (BigInteger.Zero, BigInteger.One);
            }

            // Recursive calculation using Edwards square and addition operations.
            (BigInteger, BigInteger) q = ScalarMul(p, e / _two);
            q = EdwardsSquare(q.Item1, q.Item2);
            if (!e.IsEven)
            {
                q = Edwards(q.Item1, q.Item2, p.Item1, p.Item2);
            }

            return q;
        }

        /// <summary>
        /// Encodes a BigInteger integer into a byte array representation.
        /// </summary>
        /// <param name="y">The BigInteger integer to be encoded.</param>
        /// <remarks>
        /// This function encodes a given BigInteger 'y' into a byte array representation. Encoding
        /// integers into byte arrays is a common operation in cryptography and data serialization.
        ///
        /// The function first converts the BigInteger 'y' into its binary representation using the
        /// ToByteArray method. It then ensures that the encoded representation occupies at least 32 bytes
        /// by copying the binary data into a new byte array of appropriate size.
        /// </remarks>
        /// <returns>A byte array containing the encoded representation of the input BigInteger.</returns>
        public static byte[] EncodeInt(BigInteger y)
        {
            // Convert the BigInteger 'y' into its binary representation.
            byte[] nin = y.ToByteArray();

            // Create a new byte array of size at least 32 and copy the binary data.
            byte[] nout = new byte[Math.Max(nin.Length, 32)];
            nin.CopyTo(nout.AsSpan(nout.Length - nin.Length));

            return nout;
        }

        /// <summary>
        /// Encodes an elliptic curve point (x, y) into a compressed byte array representation.
        /// </summary>
        /// <param name="x">The x-coordinate of the elliptic curve point.</param>
        /// <param name="y">The y-coordinate of the elliptic curve point.</param>
        /// <remarks>
        /// This function encodes an elliptic curve point (x, y) into a compressed byte array representation.
        /// Compressing the point representation is a common practice in elliptic curve cryptography to save space.
        ///
        /// The function first encodes the y-coordinate using the 'EncodeInt' function, resulting in a byte array.
        /// It then modifies the last byte of the y-coordinate representation to indicate whether the x-coordinate
        /// is even or odd. If x is even, the last bit of the last byte is set to 0; otherwise, it's set to 1.
        ///
        /// The resulting compressed byte array contains the encoded point (x, y) with the x-coordinate parity bit.
        /// </remarks>
        /// <returns>A compressed byte array containing the encoded representation of the point (x, y).</returns>
        public static byte[] EncodePoint(BigInteger x, BigInteger y)
        {
            byte[] nout = EncodeInt(y);

            // Set the last bit of the last byte to indicate x-coordinate parity.
            nout[^1] |= x.IsEven ? (byte)0 : (byte)128;

            return nout;
        }

        /// <summary>
        /// Retrieves the value of a specific bit from a byte array.
        /// </summary>
        /// <param name="h">The byte array containing the bits.</param>
        /// <param name="i">The index of the bit to retrieve.</param>
        /// <remarks>
        /// This function allows you to retrieve the value of a specific bit from a given byte array 'h'.
        /// The index 'i' specifies the position of the desired bit within the array.
        ///
        /// The function calculates the byte index by dividing 'i' by 8 and the bit index by taking the
        /// remainder of 'i' divided by 8. It then extracts the specified bit from the corresponding byte
        /// and returns its value (0 or 1).
        /// </remarks>
        /// <returns>The value of the specified bit (0 or 1).</returns>
        private static int GetBit(ReadOnlySpan<byte> h, int i)
        {
            // Calculate the byte and bit indexes.
            int byteIndex = i / 8;
            int bitIndex = i % 8;

            // Retrieve and return the value of the specified bit.
            return (h[byteIndex] >> bitIndex) & 1;
        }

        /// <summary>
        /// Computes the public key corresponding to a given Ed25519 signing key.
        /// </summary>
        /// <param name="signingKey">The signing key used to derive the public key.</param>
        /// <remarks>
        /// This function calculates the public key corresponding to a given Ed25519 signing key.
        /// The Ed25519 algorithm uses elliptic curve cryptography to compute the public key from
        /// the private signing key.
        ///
        /// The function first computes the SHA-512 hash of the input signing key 'signingKey' to
        /// obtain the byte array 'h'. It then uses a binary representation of 'h' to generate the
        /// public key. The process involves iterating over the bits of 'h' and adding specific
        /// powers of two to a BigInteger 'a' if the corresponding bit is set. The result 'a' is used
        /// to perform scalar multiplication with the base point '_b' to obtain the public key point.
        ///
        /// The (x, y) coordinates of the resulting public key point are then encoded into a compressed
        /// byte array using the 'EncodePoint' function.
        /// </remarks>
        /// <returns>The computed public key as a compressed byte array.</returns>
        public static byte[] PublicKey(ReadOnlySpan<byte> signingKey)
        {
            // Compute the SHA-512 hash of the signing key.
            byte[] h = SHA512.HashData(signingKey);

            // Initialize the exponent 'a' with a predefined value.
            BigInteger a = _twoPowBitLengthMinusTwo;

            // Iterate over the bits of 'h' and update 'a' accordingly.
            for (int i = 3; i < (BIT_LENGTH - 2); i++)
            {
                int bit = GetBit(h, i);
                if (bit != 0)
                {
                    a += _powerOfTwoCache[i];
                }
            }

            // Perform scalar multiplication to compute the public key point.
            (BigInteger, BigInteger) bigA = ScalarMul(_b, a);

            // Encode the resulting (x, y) coordinates into a compressed byte array.
            return EncodePoint(bigA.Item1, bigA.Item2);
        }

        /// <summary>
        /// Hashes a byte array and converts the result into a BigInteger integer.
        /// </summary>
        /// <param name="m">The input byte array to be hashed.</param>
        /// <remarks>
        /// This function calculates a hash value of the input byte array 'm' using the SHA-512 hash algorithm.
        /// The resulting hash is then interpreted as a binary representation, and a BigInteger integer 'hsum'
        /// is constructed by considering the set bits in the hash.
        ///
        /// The function iterates over the bits of the hash and, for each set bit, adds a corresponding power
        /// of two to the 'hsum' BigInteger. This effectively converts the hash into a large integer.
        /// </remarks>
        /// <returns>A BigInteger integer converted from the hash value of the input byte array.</returns>
        private static BigInteger HashInt(ReadOnlySpan<byte> m)
        {
            // Compute the SHA-512 hash of the input byte array.
            byte[] h = SHA512.HashData(m);

            // Initialize the BigInteger 'hsum' with zero.
            BigInteger hsum = BigInteger.Zero;

            // Iterate over the bits of the hash and construct the resulting BigInteger.
            for (int i = 0; i < 2 * BIT_LENGTH; i++)
            {
                int bit = GetBit(h, i);
                if (bit != 0)
                {
                    hsum += _powerOfTwoCache[i];
                }
            }

            return hsum;
        }

        /// <summary>
        /// Creates a digital signature for a given message using the Ed25519 algorithm.
        /// </summary>
        /// <param name="message">The message to be signed.</param>
        /// <param name="signingKey">The private signing key.</param>
        /// <param name="publicKey">The corresponding public key.</param>
        /// <remarks>
        /// This function generates a digital signature for a given message using the Ed25519 algorithm.
        /// The Ed25519 algorithm combines elliptic curve cryptography with hashing to create signatures.
        ///
        /// The function first derives a scalar 'a' from the signing key and message using the 'HashInt' function.
        /// It then derives a scalar 'r' in a similar manner by combining parts of the signing key and the message.
        /// The point (x, y) corresponding to 'r' is obtained using scalar multiplication.
        ///
        /// Next, the function constructs the scalar 's' by combining 'r', 'a', the encoded point 'R', the public key,
        /// and the message. The final signature is composed of the encoded point 'R' and the encoded scalar 's'.
        /// </remarks>
        /// <returns>The digital signature as a byte array.</returns>
        public static byte[] Signature(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> publicKey)
        {
            // Derive 'a' from the signing key and message.
            byte[] h = SHA512.HashData(signingKey);
            BigInteger a = _twoPowBitLengthMinusTwo;

            for (int i = 3; i < (BIT_LENGTH - 2); i++)
            {
                int bit = GetBit(h, i);
                if (bit != 0)
                {
                    a += _powerOfTwoCache[i];
                }
            }

            // Derive 'r' from a combination of the signing key and message.
            BigInteger r;
            MemoryStream rsub = new((BIT_LENGTH / 8) + message.Length);
            rsub.Write(h, BIT_LENGTH / 8, (BIT_LENGTH / 4) - (BIT_LENGTH / 8));
            rsub.Write(message);
            r = HashInt(rsub.ToArray());

            // Perform scalar multiplication to obtain the point (x, y) corresponding to 'r'.
            (BigInteger, BigInteger) bigR = ScalarMul(_b, r);

            // Construct the scalar 's' for the signature.
            BigInteger s;
            byte[] encodedBigR = EncodePoint(bigR.Item1, bigR.Item2);

            MemoryStream stemp = new(32 + publicKey.Length + message.Length);
            stemp.Write(encodedBigR);
            stemp.Write(publicKey);
            stemp.Write(message);
            s = (r + (HashInt(stemp.ToArray()) * a)) % _l;

            // Construct the final signature as a byte array.
            MemoryStream nout = new(64);
            nout.Write(encodedBigR);
            byte[] encodeInt = EncodeInt(s);
            nout.Write(encodeInt);

            return nout.ToArray();
        }

        /// <summary>
        /// Checks if a given point (x, y) lies on the Ed25519 elliptic curve.
        /// </summary>
        /// <param name="x">The x-coordinate of the point to be checked.</param>
        /// <param name="y">The y-coordinate of the point to be checked.</param>
        /// <remarks>
        /// This function verifies whether a given point (x, y) lies on the Ed25519 elliptic curve.
        /// The Ed25519 curve equation is defined by a specific prime modulus '_q' and a curve parameter '_d'.
        ///
        /// The function calculates various values related to the coordinates (x, y) and the curve parameters,
        /// and then checks if the point satisfies the curve equation. If the curve equation holds true, the
        /// point is considered to lie on the curve.
        /// </remarks>
        /// <returns>True if the point lies on the curve, false otherwise.</returns>
        private static bool IsOnCurve(BigInteger x, BigInteger y)
        {
            BigInteger xx = x * x;
            BigInteger yy = y * y;
            BigInteger dxxyy = _d * yy * xx;

            // Check if the point satisfies the curve equation and lies on the curve.
            return (yy - xx - dxxyy - 1).Mod(_q) == BigInteger.Zero;
        }

        /// <summary>
        /// Decodes a byte array representation into a BigInteger integer.
        /// </summary>
        /// <param name="s">The byte array to be decoded.</param>
        /// <remarks>
        /// This function decodes a given byte array 's' into a BigInteger integer.
        /// The function constructs the BigInteger by treating the byte array as an unsigned integer,
        /// and then applies a bitwise AND operation with a predefined mask '_un' to ensure it's within bounds.
        /// </remarks>
        /// <returns>The decoded BigInteger integer.</returns>
        // Construct a BigInteger by treating the byte array as an unsigned integer.
        // Apply a bitwise AND operation with '_un' to ensure the value is within bounds.
        private static BigInteger DecodeInt(ReadOnlySpan<byte> s) => new BigInteger(s) & _un;

        /// <summary>
        /// Decodes a compressed byte array representation into an elliptic curve point (x, y).
        /// </summary>
        /// <param name="pointBytes">The compressed byte array representing the point.</param>
        /// <remarks>
        /// This function decodes a given compressed byte array 'pointBytes' into an elliptic curve point (x, y).
        /// The decoding process involves recovering the x-coordinate 'x' from the y-coordinate 'y' using the
        /// 'RecoverX' function. The parity of the x-coordinate is adjusted based on the last bit of 'pointBytes'.
        ///
        /// The function then checks if the decoded point lies on the curve using the 'IsOnCurve' function. If
        /// the point is on the curve, it's returned as the result. If the point is not on the curve, an
        /// ArgumentException is thrown.
        /// </remarks>
        /// <returns>The (x, y) coordinates of the decoded elliptic curve point.</returns>
        /// <exception cref="ArgumentException">Thrown when the decoded point is not on the curve.</exception>
        private static (BigInteger, BigInteger) DecodePoint(ReadOnlySpan<byte> pointBytes)
        {
            // Construct a BigInteger from the compressed byte array and apply the mask '_un'.
            BigInteger y = new BigInteger(pointBytes) & _un;

            // Recover the x-coordinate from the y-coordinate.
            BigInteger x = RecoverX(y);

            // Adjust x-coordinate parity based on the last bit of 'pointBytes'.
            if ((x.IsEven ? 0 : 1) != GetBit(pointBytes, BIT_LENGTH - 1))
            {
                x = _q - x;
            }

            // Check if the decoded point lies on the curve.
            return IsOnCurve(x, y)
                ? (x, y)
                : throw new ArgumentException("Decoding point that is not on curve");
        }

        /// <summary>
        /// Checks the validity of a digital signature for a given message using the Ed25519 algorithm.
        /// </summary>
        /// <param name="signature">The digital signature to be verified.</param>
        /// <param name="message">The message that was signed.</param>
        /// <param name="publicKey">The public key corresponding to the signer's private key.</param>
        /// <remarks>
        /// This function checks the validity of a given digital signature for a specific message using the
        /// Ed25519 algorithm. The function verifies whether the signature was produced by the corresponding
        /// private key corresponding to the provided public key.
        ///
        /// The function performs several steps, including decoding the signature and public key into points
        /// on the elliptic curve, calculating the hash 'h' of the message and public key, and performing scalar
        /// multiplications using the base point '_b' and the computed values.
        ///
        /// The function then checks if the computed points satisfy a specific equality relation, which verifies
        /// the validity of the signature. If the points match, the signature is considered valid; otherwise, it's not.
        /// </remarks>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public static bool CheckValid(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
        {
            // Check the lengths of the signature and public key.
            if (signature.Length != BIT_LENGTH / 4)
            {
                throw new ArgumentException("Signature length is wrong");
            }
            else if (publicKey.Length != BIT_LENGTH / 8)
            {
                throw new ArgumentException("Public key length is wrong");
            }

            // Decode the signature point 'r' and the public key point 'a'.
            ReadOnlySpan<byte> rByte = signature[..(BIT_LENGTH / 8)];
            (BigInteger, BigInteger) r = DecodePoint(rByte);
            (BigInteger, BigInteger) a = DecodePoint(publicKey);

            // Decode the scalar 's' from the signature.
            ReadOnlySpan<byte> sByte = signature[(BIT_LENGTH / 8)..(BIT_LENGTH / 4)];
            BigInteger s = DecodeInt(sByte);
            BigInteger h;

            // Compute the hash 'h' of the encoded values.
            using MemoryStream stemp = new(32 + publicKey.Length + message.Length);
            byte[] encodePoint = EncodePoint(r.Item1, r.Item2);
            stemp.Write(encodePoint);
            stemp.Write(publicKey);
            stemp.Write(message);
            h = HashInt(stemp.ToArray());

            // Perform scalar multiplications to check the validity of the signature.
            (BigInteger, BigInteger) ra = ScalarMul(_b, s);
            (BigInteger, BigInteger) ah = ScalarMul(a, h);
            (BigInteger, BigInteger) rb = Edwards(r.Item1, r.Item2, ah.Item1, ah.Item2);

            // Check if the computed points satisfy the equality relation.
            return ra.Item1.Equals(rb.Item1) && ra.Item2.Equals(rb.Item2);
        }
    }
}
