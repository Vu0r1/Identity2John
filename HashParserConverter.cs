using System;

namespace Identity2John
{
    public static class HashParserConverter
    {

        public static string ToHex(Span<byte> raw)
        {
            var sb = new System.Text.StringBuilder();
            foreach (var rawByte in raw)
                sb.Append($"{rawByte:X2}");
            return sb.ToString().ToLowerInvariant();
        }

        /// <summary>
        /// B64 PassLib specific
        /// </summary>
        /// <param name="raw"></param>
        /// <returns></returns>
        public static string ToBase64(Span<byte> raw)
        {
            return Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '.');
        }

        public static uint ToUint(Span<byte> bin, int startIndex)
        {
            var span = bin.Slice(startIndex, 4);
            span.Reverse();
            return BitConverter.ToUInt32(span);
        }
    }
}