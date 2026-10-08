using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Newtonsoft.Json;
using SteamAuth;
using Steam_Desktop_Authenticator;

internal static class StorageWriteChecks
{
    private const string OldPassword = "ancien-mot-de-passe-fictif-stockage";
    private const string NewPassword = "nouveau-mot-de-passe-fictif-stockage";
    private const string InterruptedWriteArgument = "--simulate-interrupted-storage-write";
    private const int InterruptedWriteExitCode = 23;
    private static int checks;

    internal static int Run()
    {
        var temporaryDirectory = Path.GetFullPath(Path.GetTempPath());
        var root = Path.GetFullPath(Path.Combine(temporaryDirectory, "sda-storage-checks-" + Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(root);
        try
        {
            SaveWithLockedAccount(Path.Combine(root, "save-locked-account"));
            SaveWithLockedIndex(Path.Combine(root, "save-locked-index"));
            AddWithLockedIndex(Path.Combine(root, "add-locked-index"));
            ChangeWithLockedIndex(Path.Combine(root, "change-locked-index"));
            ChangeWithUnreadableAccount(Path.Combine(root, "change-unreadable-account"));
            ChangeWithMissingAccount(Path.Combine(root, "change-missing-account"));
            foreach (var corruption in new[] { "ciphertext", "json", "account" })
                ChangeWithCorruptAccount(Path.Combine(root, "change-corrupt-" + corruption), corruption);
            ChangeWithInterruptedWrite(Path.Combine(root, "change-interrupted-write"));
            RecoverAfterProcessExit(Path.Combine(root, "process-interrupted-write"));
            ChangeMultipleAccounts(Path.Combine(root, "change-multiple-accounts"));
            return checks;
        }
        finally
        {
            // Le seul dossier supprime est celui cree par ce test avec des comptes fictifs.
            if (!root.StartsWith(temporaryDirectory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(root).StartsWith("sda-storage-checks-", StringComparison.Ordinal))
                throw new InvalidOperationException("Le dossier fictif ne se trouve pas dans le repertoire temporaire attendu.");
            Directory.Delete(root, true);
        }
    }

    internal static bool TryRunInterruptedWrite(string[] arguments)
    {
        if (arguments.Length == 0 || arguments[0] != InterruptedWriteArgument) return false;
        if (arguments.Length != 2) throw new InvalidOperationException("Dossier fictif manquant pour le test enfant.");
        var directory = Path.GetFullPath(arguments[1]);
        var parent = Path.GetDirectoryName(directory);
        var temporaryDirectory = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (Path.GetFileName(directory) != "process-interrupted-write" ||
            parent == null || !Path.GetFileName(parent).StartsWith("sda-storage-checks-", StringComparison.Ordinal) ||
            !directory.StartsWith(temporaryDirectory, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Le processus enfant accepte uniquement le dossier fictif cree par ce test.");

        var manifest = Manifest.LoadFromDirectory(directory);
        AccountStorageTransaction.AfterAccountWrite = count =>
        {
            // Interrompt uniquement ce processus de verification, sans executer le rollback.
            if (count == 1) Environment.Exit(InterruptedWriteExitCode);
        };
        manifest.ChangeEncryptionKey(OldPassword, NewPassword);
        throw new InvalidOperationException("Le processus enfant n'a pas atteint le premier remplacement de compte.");
    }

    private static void SaveWithLockedAccount(string directory)
    {
        var fixture = CreateFixture(directory, 2);
        var snapshot = Snapshot(fixture);
        fixture.Accounts[0].Session.AccessToken = "nouvelle-session-fictive";
        using (var locked = LockForReading(fixture.AccountPath(0)))
            Check(!fixture.Manifest.SaveAccount(fixture.Accounts[0], true, OldPassword),
                "Sauvegarde refusee lorsque le maFile est verrouille");
        Unchanged(fixture, snapshot, "Echec sur maFile verrouille");
        Readable(fixture, OldPassword, "Anciennes donnees lisibles apres echec de sauvegarde");
        Check(fixture.Manifest.SaveAccount(fixture.Accounts[0], true, OldPassword),
            "Sauvegarde relancable apres liberation du maFile");
        Check(Manifest.LoadFromDirectory(directory).GetValidatedAccounts(OldPassword)[0].Session.AccessToken == "nouvelle-session-fictive",
            "Nouvelle session enregistree apres reprise de la sauvegarde");
        NamesPreserved(fixture, "Reprise conserve les noms des maFiles");
    }

    private static void SaveWithLockedIndex(string directory)
    {
        var fixture = CreateFixture(directory, 2);
        var snapshot = Snapshot(fixture);
        fixture.Accounts[0].Session.RefreshToken = "nouveau-renouvellement-fictif";
        using (var locked = LockForReading(fixture.IndexPath))
            Check(!fixture.Manifest.SaveAccount(fixture.Accounts[0], true, OldPassword),
                "Sauvegarde refusee lorsque l'index est verrouille");
        Unchanged(fixture, snapshot, "Echec de sauvegarde sur index verrouille");
        Readable(fixture, OldPassword, "Comptes lisibles avec l'ancien index apres echec");
        Check(fixture.Manifest.SaveAccount(fixture.Accounts[0], true, OldPassword),
            "Sauvegarde relancable apres liberation de l'index");
        Check(Manifest.LoadFromDirectory(directory).GetValidatedAccounts(OldPassword)[0].Session.RefreshToken == "nouveau-renouvellement-fictif",
            "Jeton de renouvellement enregistre apres reprise de la sauvegarde");
    }

    private static void AddWithLockedIndex(string directory)
    {
        var fixture = CreateFixture(directory, 1);
        var snapshot = Snapshot(fixture);
        var added = Account(1);
        using (var locked = LockForReading(fixture.IndexPath))
            Check(!fixture.Manifest.SaveAccount(added, true, OldPassword),
                "Ajout refuse lorsque l'index est verrouille");
        Unchanged(fixture, snapshot, "Echec d'ajout sur index verrouille");
        Check(fixture.Manifest.Entries.Count == 1 && Directory.GetFiles(directory, "*.maFile").Length == 1,
            "Echec d'ajout ne laisse ni entree ni maFile orphelin");
        Check(fixture.Manifest.SaveAccount(added, true, OldPassword) &&
            Manifest.LoadFromDirectory(directory).GetValidatedAccounts(OldPassword).Length == 2,
            "Ajout relancable apres liberation de l'index");
    }

    private static void ChangeWithLockedIndex(string directory)
    {
        var fixture = CreateFixture(directory, 3);
        var snapshot = Snapshot(fixture);
        using (var locked = LockForReading(fixture.IndexPath))
            Check(!fixture.Manifest.ChangeEncryptionKey(OldPassword, NewPassword),
                "Changement de mot de passe refuse lorsque l'index est verrouille");
        Unchanged(fixture, snapshot, "Echec de rechiffrement sur index verrouille");
        Readable(fixture, OldPassword, "Tous les comptes restent lisibles avec l'ancien mot de passe");
        Check(fixture.Manifest.ChangeEncryptionKey(OldPassword, NewPassword),
            "Rechiffrement relancable apres liberation de l'index");
        Readable(fixture, NewPassword, "Tous les comptes lisibles apres reprise du rechiffrement");
        NamesPreserved(fixture, "Reprise du rechiffrement conserve les noms");
    }

    private static void ChangeWithUnreadableAccount(string directory)
    {
        var fixture = CreateFixture(directory, 3);
        var snapshot = Snapshot(fixture);
        using (var locked = new FileStream(fixture.AccountPath(2), FileMode.Open, FileAccess.Read, FileShare.None))
            Check(!fixture.Manifest.ChangeEncryptionKey(OldPassword, NewPassword),
                "Dernier compte inaccessible empeche le rechiffrement");
        Unchanged(fixture, snapshot, "Dernier compte inaccessible");
        Readable(fixture, OldPassword, "Comptes precedents non reecrits avant validation du dernier");
        Check(fixture.Manifest.ChangeEncryptionKey(OldPassword, NewPassword),
            "Rechiffrement relancable apres liberation du dernier compte");
        Readable(fixture, NewPassword, "Comptes lisibles apres liberation du dernier compte");
    }

    private static void ChangeWithMissingAccount(string directory)
    {
        var fixture = CreateFixture(directory, 3);
        var path = fixture.AccountPath(2);
        var original = File.ReadAllBytes(path);
        File.Delete(path);
        var snapshot = Snapshot(fixture);
        Check(!fixture.Manifest.ChangeEncryptionKey(OldPassword, NewPassword),
            "Compte indexe absent empeche le rechiffrement");
        Unchanged(fixture, snapshot, "Dernier compte absent");
        File.WriteAllBytes(path, original);
        Check(fixture.Manifest.ChangeEncryptionKey(OldPassword, NewPassword),
            "Rechiffrement relancable apres restauration du compte absent");
        Readable(fixture, NewPassword, "Comptes lisibles apres restauration du compte absent");
    }

    private static void ChangeWithCorruptAccount(string directory, string corruption)
    {
        var fixture = CreateFixture(directory, 3);
        var index = corruption == "ciphertext" ? 1 : 2;
        var path = fixture.AccountPath(index);
        var original = File.ReadAllBytes(path);
        var entry = fixture.Manifest.Entries[index];
        string corrupted;
        if (corruption == "ciphertext") corrupted = "not-base64-ciphertext";
        else
        {
            var invalidAccount = Account(index);
            invalidAccount.IdentitySecret = null;
            var plaintext = corruption == "json" ? "null" : JsonConvert.SerializeObject(invalidAccount);
            corrupted = FileEncryptor.EncryptData(OldPassword, entry.Salt, entry.IV, plaintext);
        }
        File.WriteAllText(path, corrupted);
        var snapshot = Snapshot(fixture);
        Check(!fixture.Manifest.ChangeEncryptionKey(OldPassword, NewPassword),
            "Compte corrompu empeche le rechiffrement (" + corruption + ")");
        Unchanged(fixture, snapshot, "Compte corrompu (" + corruption + ")");
        File.WriteAllBytes(path, original);
        Check(fixture.Manifest.ChangeEncryptionKey(OldPassword, NewPassword),
            "Rechiffrement relancable apres restauration du compte corrompu (" + corruption + ")");
        Readable(fixture, NewPassword, "Comptes lisibles apres restauration (" + corruption + ")");
    }

    private static void ChangeMultipleAccounts(string directory)
    {
        var fixture = CreateFixture(directory, 3);
        Check(fixture.Manifest.ChangeEncryptionKey(OldPassword, NewPassword),
            "Changement de mot de passe de plusieurs comptes");
        Readable(fixture, NewPassword, "Secrets de tous les comptes conserves apres changement de mot de passe");
        NamesPreserved(fixture, "Changement de mot de passe conserve les noms de transfert");
        Check(fixture.Manifest.ChangeEncryptionKey(NewPassword, null),
            "Dechiffrement de plusieurs comptes pour export");
        Readable(fixture, null, "Comptes exportes lisibles");
        NamesPreserved(fixture, "Export conserve les noms des maFiles");
        Check(fixture.Manifest.ChangeEncryptionKey(null, OldPassword),
            "Rechiffrement de tous les comptes apres export");
        Readable(fixture, OldPassword, "Secrets conserves apres export et rechiffrement");
        NamesPreserved(fixture, "Rechiffrement apres export ne cree pas de maFile orphelin");
        Check(Directory.GetFiles(directory, "*", SearchOption.AllDirectories).Length == fixture.Accounts.Length + 1,
            "Succes du rechiffrement ne laisse aucun journal ni fichier temporaire");
        Check(Directory.GetFiles(directory, "*", SearchOption.AllDirectories).All(path =>
            !File.ReadAllText(path).Contains("\"shared_secret\"", StringComparison.Ordinal) &&
            !File.ReadAllText(path).Contains("\"identity_secret\"", StringComparison.Ordinal)),
            "Aucun secret de compte en clair dans les fichiers conserves apres rechiffrement");
    }

    private static void ChangeWithInterruptedWrite(string directory)
    {
        var fixture = CreateFixture(directory, 3);
        var snapshot = Snapshot(fixture);
        bool firstAccountReplaced = false;
        AccountStorageTransaction.AfterAccountWrite = count =>
        {
            if (count != 1) return;
            firstAccountReplaced = true;
            throw new IOException("Panne fictive apres le premier remplacement de compte.");
        };
        try
        {
            Check(!fixture.Manifest.ChangeEncryptionKey(OldPassword, NewPassword),
                "Panne apres un remplacement interrompt le rechiffrement");
        }
        finally { AccountStorageTransaction.AfterAccountWrite = null; }
        Check(firstAccountReplaced, "Simulation de panne atteint un compte deja remplace");
        Unchanged(fixture, snapshot, "Panne apres remplacement du premier compte");
        Readable(fixture, OldPassword, "Rollback restaure tous les comptes avec l'ancien mot de passe");
        Check(fixture.Manifest.ChangeEncryptionKey(OldPassword, NewPassword),
            "Rechiffrement relancable apres rollback");
        Readable(fixture, NewPassword, "Tous les comptes lisibles apres reprise du rollback");
    }

    private static void RecoverAfterProcessExit(string directory)
    {
        var fixture = CreateFixture(directory, 3);
        var snapshot = Snapshot(fixture);
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Executable de verification introuvable.");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = directory
        };
        if (string.Equals(Path.GetFileNameWithoutExtension(executable), "dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Assembly.GetEntryAssembly().Location);
        start.ArgumentList.Add(InterruptedWriteArgument);
        start.ArgumentList.Add(directory);
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Le processus de verification enfant n'a pas demarre.");
        if (!child.WaitForExit(30000))
        {
            // Le seul processus termine est l'enfant que ce test vient de creer.
            child.Kill();
            child.WaitForExit(5000);
            throw new InvalidOperationException("Le processus de verification enfant n'a pas atteint son point d'arret.");
        }
        Check(child.ExitCode == InterruptedWriteExitCode, "Processus fictif arrete juste apres le premier remplacement");
        Check(!File.ReadAllBytes(fixture.AccountPath(0)).SequenceEqual(snapshot.Files[fixture.Filenames[0]]) &&
            File.ReadAllBytes(fixture.IndexPath).SequenceEqual(snapshot.Files["manifest.json"]),
            "Interruption laisse un compte remplace avant la validation du nouvel index");
        var newFiles = Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
            .Where(path => !snapshot.Files.ContainsKey(Path.GetRelativePath(directory, path))).ToArray();
        Check(newFiles.Length > 0, "Journal de recuperation conserve apres interruption du processus");
        var secrets = fixture.Accounts.SelectMany(account => new[]
            { account.SharedSecret, account.IdentitySecret, account.Session.AccessToken, account.RevocationCode }).ToArray();
        Check(newFiles.All(path =>
        {
            var contents = Encoding.UTF8.GetString(File.ReadAllBytes(path));
            return !contents.Contains("\"shared_secret\"", StringComparison.Ordinal) &&
                !contents.Contains("\"identity_secret\"", StringComparison.Ordinal) &&
                secrets.All(secret => !contents.Contains(secret, StringComparison.Ordinal));
        }), "Journal et fichiers intermediaires ne contiennent aucun secret fictif en clair");

        var recovered = Manifest.LoadFromDirectory(directory);
        Check(JsonConvert.SerializeObject(recovered) == snapshot.Memory,
            "Rechargement restaure l'index original depuis le journal");
        Unchanged(fixture, snapshot, "Recuperation apres interruption du processus");
        Readable(fixture, OldPassword, "Rechargement restaure tous les secrets avec l'ancien mot de passe");
        Check(recovered.ChangeEncryptionKey(OldPassword, NewPassword),
            "Rechiffrement relancable apres recuperation du journal");
        Readable(fixture, NewPassword, "Comptes lisibles apres reprise depuis le journal");
    }

    private static Fixture CreateFixture(string directory, int count)
    {
        Directory.CreateDirectory(directory);
        var accounts = Enumerable.Range(0, count).Select(Account).ToArray();
        var entries = accounts.Select((account, index) => new Manifest.ManifestEntry
        {
            SteamID = account.Session.SteamID,
            Filename = "fictitious-transfer-" + index + ".maFile",
            Salt = FileEncryptor.GetRandomSalt(), IV = FileEncryptor.GetInitializationVector()
        }).ToList();
        for (var index = 0; index < count; index++)
            File.WriteAllText(Path.Combine(directory, entries[index].Filename), FileEncryptor.EncryptData(
                OldPassword, entries[index].Salt, entries[index].IV, JsonConvert.SerializeObject(accounts[index])));
        File.WriteAllText(Path.Combine(directory, "manifest.json"), JsonConvert.SerializeObject(new Manifest
        {
            Encrypted = true, FirstRun = false, Entries = entries,
            PeriodicChecking = true, PeriodicCheckingInterval = 11, CheckAllAccounts = true
        }));
        return new Fixture(directory, Manifest.LoadFromDirectory(directory), accounts, entries.Select(entry => entry.Filename).ToArray());
    }

    private static SteamGuardAccount Account(int index) => new SteamGuardAccount
    {
        AccountName = "fictitious-storage-account-" + index,
        SharedSecret = Convert.ToBase64String(Enumerable.Repeat((byte)(42 + index), 20).ToArray()),
        IdentitySecret = Convert.ToBase64String(Enumerable.Repeat((byte)(52 + index), 20).ToArray()),
        DeviceID = "android:fictitious-storage-device-" + index,
        RevocationCode = "R0000" + index, FullyEnrolled = true,
        Session = new SessionData
        {
            SteamID = 76561198000000000UL + (ulong)index,
            AccessToken = "fictitious-storage-access-" + index,
            RefreshToken = "fictitious-storage-refresh-" + index
        }
    };

    private static FileStream LockForReading(string path) =>
        new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);

    private static (string Memory, Dictionary<string, byte[]> Files) Snapshot(Fixture fixture) =>
        (JsonConvert.SerializeObject(fixture.Manifest), Directory.GetFiles(fixture.Directory, "*", SearchOption.AllDirectories)
            .ToDictionary(path => Path.GetRelativePath(fixture.Directory, path), File.ReadAllBytes));

    private static void Unchanged(Fixture fixture, (string Memory, Dictionary<string, byte[]> Files) before, string label)
    {
        var after = Snapshot(fixture);
        Check(after.Memory == before.Memory, label + " : index en memoire inchange");
        Check(before.Files.Count == after.Files.Count && before.Files.All(file =>
            after.Files.TryGetValue(file.Key, out var bytes) && bytes.SequenceEqual(file.Value)),
            label + " : index et comptes sur disque inchanges");
    }

    private static void Readable(Fixture fixture, string password, string label)
    {
        var manifest = Manifest.LoadFromDirectory(fixture.Directory);
        var restored = manifest.GetValidatedAccounts(password);
        Check(restored.Length == fixture.Accounts.Length && restored.Select((account, index) =>
            account.Session.SteamID == fixture.Accounts[index].Session.SteamID &&
            account.SharedSecret == fixture.Accounts[index].SharedSecret &&
            account.IdentitySecret == fixture.Accounts[index].IdentitySecret &&
            account.RevocationCode == fixture.Accounts[index].RevocationCode).All(value => value), label);
        Check(manifest.PeriodicChecking && manifest.PeriodicCheckingInterval == 11 && manifest.CheckAllAccounts,
            label + " : preferences de l'index conservees");
    }

    private static void NamesPreserved(Fixture fixture, string label)
    {
        var manifest = Manifest.LoadFromDirectory(fixture.Directory);
        Check(manifest.Entries.Select(entry => entry.Filename).SequenceEqual(fixture.Filenames) &&
            Directory.GetFiles(fixture.Directory, "*.maFile").Select(Path.GetFileName).OrderBy(name => name)
                .SequenceEqual(fixture.Filenames.OrderBy(name => name)), label);
    }

    private static void Check(bool condition, string label)
    {
        if (!condition) throw new InvalidOperationException(label);
        checks++;
        Console.WriteLine("OK: " + label);
    }

    private sealed record Fixture(string Directory, Manifest Manifest, SteamGuardAccount[] Accounts, string[] Filenames)
    {
        internal string IndexPath => Path.Combine(Directory, "manifest.json");
        internal string AccountPath(int index) => Path.Combine(Directory, Filenames[index]);
    }
}
