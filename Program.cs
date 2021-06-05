using System;
using System.Reflection;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.AspNetCore.Identity;

namespace Identity2John
{
    [VersionOptionFromMember(MemberName = nameof(GetVersion))]
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

        [Option(ShortName = "s")]
        public string Hash { get; } = "";

        [Option(ShortName = "S")]
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
                Console.Error.WriteLine($"Error : Invalide file : '{HashFile}'.");
                return;
            }
            foreach (var line in System.IO.File.ReadLines(HashFile))
            {
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