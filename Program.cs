using System;
using System.Reflection;
using McMaster.Extensions.CommandLineUtils;

namespace Identity2John
{
    [VersionOptionFromMember(MemberName = nameof(GetVersion))]
    [Command(Description = @"Convert a Base64 password hash (PBKDF2-HMAC-SHA1/PBKDF2-HMAC-SHA256/PBKDF2-HMAC-SHA512) generated by Microsft.Identity (V2 or V3) to JohnTheRipper input format.
If no option, read standard input.", FullName = "Identity2John")]
    public class Program
    {
        public static int Main(string[] args)
        {
            try
            {
                return CommandLineApplication.Execute<Program>(args);
            }
            catch (Exception e)
            {
                Console.Error.Write(e.Message);
                return -1;
            }
        }

        [Option(CommandOptionType.SingleValue, ShortName = "s", LongName = "hash", Description = "[user:]base64Hash")]
        public string Hash { get; } = "";

        [Option(CommandOptionType.SingleValue, ShortName = "S", LongName = "hashes", Description = "A file with a [user:]base64Hash by line"),
            FileExists()]
        public string HashFile { get; } = "";

        private static string GetVersion() => typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

        private void OnExecute()
        {
            var parser = new IdentityHashParser();
            if (!string.IsNullOrEmpty(Hash))
                ParseLine(parser, Hash);
            else if (!string.IsNullOrEmpty(HashFile))
                ParseFile(parser);
            else
                ParseLine(parser, Console.ReadLine());
        }

        private void ParseFile(IHashParser parser)
        {
            if (!System.IO.File.Exists(HashFile))
            {
                Console.Error.WriteLine($"Error : Invalid file : '{HashFile}'.");
                return;
            }
            foreach (var line in System.IO.File.ReadLines(HashFile))
            {
                if (line.StartsWith("#"))
                    continue;
                ParseLine(parser, line);
            }
        }

        private static void ParseLine(IHashParser parser, string line)
        {
            line = line.Trim();
            var res = parser.Parse(line);
            if (string.IsNullOrEmpty(res))
            {
                Console.Error.WriteLine($"Error : Invalid PasswordHash : '{line}'.");
            }
            else
            {
                Console.Out.WriteLine(res);
            }
        }
    }
}