using System;
using System.IO;
using System.Linq;

namespace GitoliteWrapper;

internal static class Program
{
    // TODO: Don't hardcode the path to gitolite-shell.
    private const string GitoliteShellPath = "/usr/bin/gitolite-shell";

    public static int Main(string[] args)
    {
        var parseOnly = args.Any(a => a is "-t" or "--test");
        var username = string.Empty;

        if (ReadUserAuthContents(out var userAuth))
        {
            var (keyTypeRange, keyRange) = UserAuthParser.FindPublicKey(userAuth);
            var keyType = userAuth[keyTypeRange];
            var key = userAuth[keyRange];

            if (keyType.IsSupportedCertType() && key.DecodeBase64(out var decodedKey))
                username = decodedKey.FindGitoliteUser();
        }

        if (!parseOnly)
        {
            string[] shellArgs = username.Length > 0 ? [username] : [];
            // TODO: errCode and errDescription should be logged.
            var (errCode, errDescription) = Posix.Exec(GitoliteShellPath, shellArgs);
            return 1;
        }

        if (username.Length == 0)
            return 1;

        Console.Out.WriteLine(username);
        return 0;
    }

    private static bool ReadUserAuthContents(out ReadOnlySpan<byte> content)
    {
        var path = Environment.GetEnvironmentVariable("SSH_USER_AUTH");
        if (!string.IsNullOrEmpty(path))
        {
            var data = File.ReadAllBytes(path);
            if (data.Length > 0)
            {
                content = new ReadOnlySpan<byte>(data);
                return true;
            }
        }

        content = ReadOnlySpan<byte>.Empty;
        return false;
    }
}
