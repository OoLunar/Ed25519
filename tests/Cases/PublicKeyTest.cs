using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace System.Security.Cryptography.Tests
{
    [TestClass]
    public class PublicKeyTests
    {
        // Test vectors from RFC8032, section 7.1
        private static readonly string[] _privateKeysHex = new string[]
        {
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
        };

        private static readonly string[] _expectedPublicKeysHex = new string[]
        {
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        };

        [TestMethod]
        public void TestPublicKeyGenerationRFC8032()
        {
            // Arrange
            Span<byte> privateKey = stackalloc byte[32];
            Span<byte> expectedPublicKey = stackalloc byte[32];
            for (int i = 0; i < _privateKeysHex.Length; i++)
            {
                FromHex(_privateKeysHex[i], privateKey);
                FromHex(_expectedPublicKeysHex[i], expectedPublicKey);

                // Act
                byte[] generatedPublicKey = Ed25519.PublicKey(privateKey);

                // Assert
                Assert.AreEqual(expectedPublicKey.Length, generatedPublicKey.Length, $"Length mismatch for test vector {i + 1}.");
                for (int j = 0; j < expectedPublicKey.Length; j++)
                {
                    Assert.AreEqual(expectedPublicKey[j].ToString("X2"), generatedPublicKey[j].ToString("X2"), $"Byte mismatch at index {j} for test vector {i + 1}.");
                }
            }
        }

        private static void FromHex(ReadOnlySpan<char> hex, Span<byte> destination)
        {
            if ((hex.Length & 1) == 1)
            {
                throw new ArgumentException("Hex string must have an even number of characters.");
            }
            else if (destination.Length < hex.Length / 2)
            {
                throw new ArgumentException("Destination buffer is too small.");
            }

            for (int i = 0, j = 0; i < hex.Length; i += 2, j++)
            {
                byte highNibble = HexCharToByte(hex[i]);
                byte lowNibble = HexCharToByte(hex[i + 1]);
                destination[j] = (byte)((highNibble << 4) | lowNibble);
            }
        }

        private static byte HexCharToByte(char c) => c switch
        {
            >= '0' and <= '9' => (byte)(c - '0'),
            >= 'a' and <= 'f' => (byte)(c - 'a' + 10),
            >= 'A' and <= 'F' => (byte)(c - 'A' + 10),
            _ => throw new ArgumentException($"Invalid hex character '{c}'."),
        };
    }
}
