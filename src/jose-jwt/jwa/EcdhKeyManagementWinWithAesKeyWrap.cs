using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Jose
{
    public class EcdhKeyManagementWinWithAesKeyWrap : EcdhKeyManagementWin
    {
        private readonly AesKeyWrapManagement aesKW;
        private readonly int keyLengthBits;
        private readonly EcdhKeyManagementUnixWithAesKeyWrap ecdhKeyManagementUnixWithAesKeyWrap;

        public EcdhKeyManagementWinWithAesKeyWrap(int keyLengthBits, AesKeyWrapManagement aesKw, EcdhKeyManagementUnixWithAesKeyWrap ecdhKeyManagementUnixWithAesKeyWrap) : base(false, ecdhKeyManagementUnixWithAesKeyWrap)
        {
            aesKW = aesKw;
            this.keyLengthBits = keyLengthBits;
            this.ecdhKeyManagementUnixWithAesKeyWrap = ecdhKeyManagementUnixWithAesKeyWrap;
        }

        public override byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
        {
            if (key is ECDiffieHellman)
            {
                return ecdhKeyManagementUnixWithAesKeyWrap.WrapNewKey(cekSizeBits, key, header);
            }
            
            var cek = Arrays.Random(cekSizeBits);

            return new byte[][] { cek, this.WrapKey(cek, key, header) };
        }

        public override byte[] WrapKey(byte[] cek, object key, IDictionary<string, object> header)
        {
            if (key is ECDiffieHellman)
            {
                return ecdhKeyManagementUnixWithAesKeyWrap.WrapKey(cek, key, header);
            }
            
            byte[][] agreement = base.WrapNewKey(keyLengthBits, key, header);

            byte[] kek = agreement[0]; //use agreed key as KEK for AES-KW

            return aesKW.WrapKey(cek, kek, header);
        }

        public override byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
        {
            if (key is ECDiffieHellman)
            {
                return ecdhKeyManagementUnixWithAesKeyWrap.Unwrap(encryptedCek, key, cekSizeBits, header);
            }
            
            byte[] kek = base.Unwrap(Arrays.Empty, key, keyLengthBits, header);

            return aesKW.Unwrap(encryptedCek, kek, cekSizeBits, header);
        }
    }
}