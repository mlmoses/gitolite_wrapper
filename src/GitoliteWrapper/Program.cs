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
        var userAuth = ReadUserAuthContents();

        var username = string.Empty;
        if (userAuth != null)
        {
            var (keyType, key) = UserAuthParser.FindPublicKey(userAuth);
            if (SshPublicKey.IsSupportedCertType(keyType))
            {
                var decodedKey = ByteString.FromBase64(key);
                if (decodedKey != null)
                    username = SshPublicKey.FindGitoliteUser(decodedKey);
            }
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

    private static ByteString? ReadUserAuthContents()
    {
        var sshUserAuth = Environment.GetEnvironmentVariable("SSH_USER_AUTH");
        if (string.IsNullOrEmpty(sshUserAuth))
            return null;

        FileStream? stream = null;
        try
        {
            stream = new FileStream(sshUserAuth, FileMode.Open, FileAccess.Read, FileShare.None);
            return ByteString.From(stream);
        }
        catch
        {
            // TODO: Log this exception.
            return null;
        }
        finally
        {
            stream?.Dispose();
        }
    }
}