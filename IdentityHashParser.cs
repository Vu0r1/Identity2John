using System;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Identity2John
{
    public interface IHashParser
    {
        string Parse(string line);
    }

    /// <summary>
    /// Based on https://www.blinkingcaret.com/2017/11/29/asp-net-identity-passwordhash/
    /// </summary>
    public class IdentityHashParser : IHashParser
    {
        public string Parse(string line)
        {
            try
            {
                if (line.Contains(':'))
                {
                    var parts = line.Split(':', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2)
                        return $"{parts[0]}:{ConvertHash(parts[1])}";
                    return ConvertHash(parts[0]);
                }
                return ConvertHash(line);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Detail : '{ex.Message}'.");
                return null;
            }
        }

        private static string ConvertHash(string hash)
        {
            if (hash.Length < 49)
                return null;

            var bin = Convert.FromBase64String(hash);
            return bin[0] switch
            {
                0x00 => ParseV2(bin),
                0x01 => ParseV3(bin),
                _ => null,
            };
        }

        private static string ParseV2(Span<byte> bin)
        {
            if (bin.Length != 49)
                return null;
            return $"$PBKDF2-HMAC-SHA1$1000.{HashParserConverter.ToHex(bin[1..17])}.{HashParserConverter.ToHex(bin[17..])}";
        }

        private static string ParseV3(Span<byte> bin)
        {
            if (bin.Length != 61)
                return null;
            var iterations = HashParserConverter.ToUint(bin, 5);
            switch ((KeyDerivationPrf)HashParserConverter.ToUint(bin, 1))
            {
                case KeyDerivationPrf.HMACSHA1:
                    return $"$PBKDF2-HMAC-SHA1${iterations}.{HashParserConverter.ToHex(bin[13..29])}.{HashParserConverter.ToHex(bin[29..61])}";
                case KeyDerivationPrf.HMACSHA256:
                    return $"$pbkdf2-sha256${iterations}${HashParserConverter.ToBase64(bin[13..29])}${HashParserConverter.ToBase64(bin[29..61])}";
                case KeyDerivationPrf.HMACSHA512:
                    return $"$pbkdf2-hmac-sha512${iterations}.{HashParserConverter.ToHex(bin[13..29])}.{HashParserConverter.ToHex(bin[29..61])}";
                default:
                    return null;
            }
        }
    }
}