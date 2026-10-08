using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using ProtoBuf;
using SteamAuth;
using SteamKit2.Internal;
using Steam_Desktop_Authenticator;

internal static class RecoveryChecks
{
    private const string BackupPassword = "mot-de-passe-fictif-sauvegarde";
    private const string CurrentPassword = "nouveau-mot-de-passe-fictif";
    private const ulong SteamId = 76561198000001000;
    private static int checks;

    internal static int Run()
    {
        var root = Path.Combine(Path.GetTempPath(), "sda-recovery-checks-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            RecoverCorruptAccount(Path.Combine(root, "single"), 1, 0, false);
            RecoverCorruptAccount(Path.Combine(root, "first"), 3, 0, true);
            RecoverCorruptAccount(Path.Combine(root, "middle"), 3, 1, true);
            RefuseWrongPassword(Path.Combine(root, "wrong-password"));
            RefuseUnreadableOtherAccount(Path.Combine(root, "other-unreadable"));
            RefuseHealthyAccount(Path.Combine(root, "healthy"));
            RefuseLockedAccount(Path.Combine(root, "locked-account"));
            RetryAfterIndexFailure(Path.Combine(root, "locked-index"));
            foreach (var defect in new[] { "empty-object", "missing-session", "invalid-shared-secret", "invalid-identity-secret" })
                RecoverIncompleteAccount(Path.Combine(root, defect), defect);
            return checks;
        }
        finally
        {
            // Exclusivement le dossier aleatoire contenant ces donnees fictives.
            Directory.Delete(root, true);
        }
    }

    private static void RecoverCorruptAccount(string directory, int count, int targetIndex, bool changedPassword)
    {
        var fixture = CreateFixture(directory, count, targetIndex, changedPassword);
        File.WriteAllText(fixture.TargetPath, "invalid-base64-target!");
        var before = Snapshot(directory);
        var memoryBefore = JsonConvert.SerializeObject(fixture.Manifest);
        var entriesBefore = fixture.Manifest.Entries.Select(JsonConvert.SerializeObject).ToArray();

        Check(TransferBackup.ValidateRecovery(directory, fixture.Manifest, fixture.Account, fixture.Password),
            "Recuperation detecte le compte indexe meme si son maFile est invalide");
        AssertUnchanged(directory, before, fixture.Manifest, memoryBefore,
            "Validation seule sans ecriture ni modification en memoire");
        TransferBackup.RecoverAccount(directory, fixture.Manifest, fixture.Account, fixture.Password);

        var reloaded = Manifest.LoadFromDirectory(directory);
        var restored = reloaded.GetValidatedAccounts(fixture.Password);
        Check(reloaded.Entries.Count == count && restored.Length == count &&
            reloaded.Entries[targetIndex].SteamID == fixture.Account.Session.SteamID &&
            reloaded.Entries[targetIndex].Filename != Path.GetFileName(fixture.TargetPath),
            "Recuperation remplace seulement l'entree cible a sa position dans l'index");
        var account = restored.Single(a => a.Session.SteamID == fixture.Account.Session.SteamID);
        Check(account.SharedSecret == fixture.Account.SharedSecret &&
            account.IdentitySecret == fixture.Account.IdentitySecret &&
            account.RevocationCode == fixture.Account.RevocationCode && account.FullyEnrolled,
            "Compte restaure lisible avec le mot de passe actuel et tous ses secrets");
        Check(File.ReadAllBytes(fixture.TargetPath).SequenceEqual(before[Path.GetFileName(fixture.TargetPath)]),
            "Ancien maFile corrompu conserve exactement");
        Check(reloaded.Entries.Where((_, i) => i != targetIndex).Select(JsonConvert.SerializeObject)
            .SequenceEqual(entriesBefore.Where((_, i) => i != targetIndex)),
            "Entrees des autres comptes conservees exactement");
        Check(!reloaded.FirstRun && reloaded.PeriodicChecking &&
            reloaded.PeriodicCheckingInterval == 17 && reloaded.CheckAllAccounts &&
            !reloaded.AutoConfirmTrades && !reloaded.AutoConfirmMarketTransactions,
            "Reglages existants preserves pendant la recuperation");
        foreach (var other in reloaded.Entries.Where((_, i) => i != targetIndex))
            Check(File.ReadAllBytes(Path.Combine(directory, other.Filename)).SequenceEqual(before[other.Filename]),
                "Autre maFile conserve octet pour octet");
        var indexCopies = Directory.GetFiles(directory, "manifest.json.before-recovery-*.bak");
        Check(indexCopies.Length == 1 && File.ReadAllBytes(indexCopies[0]).SequenceEqual(before["manifest.json"]),
            "Index original conserve octet pour octet avant remplacement");
        Check(JsonConvert.SerializeObject(fixture.Manifest) == JsonConvert.SerializeObject(reloaded),
            "Index en memoire actualise seulement apres sauvegarde reussie");
        AssertBackupIntact(fixture, before);
        Check(Directory.GetFiles(directory, "*.tmp").Length == 0,
            "Recuperation ne laisse aucun fichier temporaire");
    }

    private static void RefuseWrongPassword(string directory)
    {
        var fixture = CreateFixture(directory, 3, 0, true);
        File.WriteAllText(fixture.TargetPath, "invalid-base64-target!");
        var before = Snapshot(directory);
        var memoryBefore = JsonConvert.SerializeObject(fixture.Manifest);
        Throws<InvalidOperationException>(() => TransferBackup.ValidateRecovery(directory, fixture.Manifest,
            fixture.Account, BackupPassword), "Ancien mot de passe du backup refuse pour les comptes rechiffres");
        Throws<InvalidOperationException>(() => TransferBackup.RecoverAccount(directory, fixture.Manifest,
            fixture.Account, BackupPassword), "Recuperation revalide le mot de passe avant toute ecriture");
        AssertUnchanged(directory, before, fixture.Manifest, memoryBefore,
            "Mauvais mot de passe ne modifie aucun fichier ni l'index en memoire");
    }

    private static void RefuseUnreadableOtherAccount(string directory)
    {
        var fixture = CreateFixture(directory, 3, 0, false);
        File.WriteAllText(fixture.TargetPath, "invalid-base64-target!");
        File.WriteAllText(Path.Combine(directory, fixture.Manifest.Entries[2].Filename), "invalid-base64-other!");
        var before = Snapshot(directory);
        var memoryBefore = JsonConvert.SerializeObject(fixture.Manifest);
        Throws<InvalidOperationException>(() => TransferBackup.ValidateRecovery(directory, fixture.Manifest,
            fixture.Account, fixture.Password), "Tous les autres comptes sont verifies, y compris le dernier");
        Throws<InvalidOperationException>(() => TransferBackup.RecoverAccount(directory, fixture.Manifest,
            fixture.Account, fixture.Password), "Autre compte illisible empeche aussi l'ecriture directe");
        AssertUnchanged(directory, before, fixture.Manifest, memoryBefore,
            "Refus pour autre compte illisible sans modification");
    }

    private static void RefuseHealthyAccount(string directory)
    {
        var fixture = CreateFixture(directory, 1, 0, false);
        var before = Snapshot(directory);
        var memoryBefore = JsonConvert.SerializeObject(fixture.Manifest);
        var liveAccount = fixture.Manifest.GetAllAccounts(fixture.Password).Single();
        Check(liveAccount.SharedSecret != fixture.Account.SharedSecret,
            "Ancienne sauvegarde fictive contient des secrets differents du compte sain");
        Throws<InvalidOperationException>(() => TransferBackup.ValidateRecovery(directory, fixture.Manifest,
            fixture.Account, fixture.Password), "Ancien backup refuse si le compte indexe est sain");
        Throws<InvalidOperationException>(() => TransferBackup.RecoverAccount(directory, fixture.Manifest,
            fixture.Account, fixture.Password), "Recuperation directe ne remplace pas les secrets d'un compte sain");
        Throws<InvalidOperationException>(() => TransferBackup.SaveAccount(directory, fixture.Manifest,
            fixture.Account, fixture.Password), "Enregistrement normal continue de refuser un doublon");
        AssertUnchanged(directory, before, fixture.Manifest, memoryBefore,
            "Compte sain et son index inchanges apres refus d'un ancien backup");
    }

    private static void RefuseLockedAccount(string directory)
    {
        var fixture = CreateFixture(directory, 1, 0, false);
        var before = Snapshot(directory);
        var memoryBefore = JsonConvert.SerializeObject(fixture.Manifest);
        using (var locked = new FileStream(fixture.TargetPath, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            ThrowsIo(() => TransferBackup.ValidateRecovery(directory, fixture.Manifest, fixture.Account, fixture.Password),
                "Erreur de lecture du maFile non assimilee a une corruption recuperable");
            ThrowsIo(() => TransferBackup.RecoverAccount(directory, fixture.Manifest, fixture.Account, fixture.Password),
                "MaFile inaccessible empeche sa recuperation");
        }
        AssertUnchanged(directory, before, fixture.Manifest, memoryBefore,
            "Verrouillage du maFile ne modifie aucun fichier ni l'index");
    }

    private static void RetryAfterIndexFailure(string directory)
    {
        var fixture = CreateFixture(directory, 3, 1, true);
        File.WriteAllText(fixture.TargetPath, "invalid-base64-target!");
        var before = Snapshot(directory);
        var memoryBefore = JsonConvert.SerializeObject(fixture.Manifest);
        using (var locked = new FileStream(Path.Combine(directory, "manifest.json"), FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            ThrowsIo(() => TransferBackup.RecoverAccount(directory, fixture.Manifest, fixture.Account, fixture.Password),
                "Echec de remplacement d'un index verrouille remonte a l'appelant");
        }
        Check(JsonConvert.SerializeObject(fixture.Manifest) == memoryBefore && before.All(pair =>
            File.ReadAllBytes(Path.Combine(directory, pair.Key)).SequenceEqual(pair.Value)),
            "Echec d'ecriture conserve index, compte cible, autres comptes et etat memoire");
        TransferBackup.RecoverAccount(directory, fixture.Manifest, fixture.Account, fixture.Password);
        var restored = Manifest.LoadFromDirectory(directory).GetAllAccounts(fixture.Password);
        Check(restored.Length == 3 && restored.Single(a => a.Session.SteamID == fixture.Account.Session.SteamID)
            .SharedSecret == fixture.Account.SharedSecret,
            "Recuperation relancable apres liberation de l'index sans nouveau transfert");
        Check(File.ReadAllBytes(fixture.TargetPath).SequenceEqual(before[Path.GetFileName(fixture.TargetPath)]) &&
            Directory.GetFiles(directory, "manifest.json.before-recovery-*.bak").All(path =>
                File.ReadAllBytes(path).SequenceEqual(before["manifest.json"])),
            "Nouvelle tentative preserve encore l'ancien maFile et les copies exactes de l'index");
        AssertBackupIntact(fixture, before);
    }

    private static void RecoverIncompleteAccount(string directory, string defect)
    {
        var fixture = CreateFixture(directory, 2, 1, true);
        var account = Account(1, 11);
        if (defect == "missing-session") account.Session = null;
        if (defect == "invalid-shared-secret") account.SharedSecret = "invalid-base64-secret!";
        if (defect == "invalid-identity-secret") account.IdentitySecret = "invalid-base64-identity!";
        var plaintext = defect == "empty-object" ? "{}" : JsonConvert.SerializeObject(account);
        var entry = fixture.Manifest.Entries[1];
        File.WriteAllText(fixture.TargetPath, FileEncryptor.EncryptData(fixture.Password, entry.Salt, entry.IV, plaintext));
        var before = Snapshot(directory);
        var memoryBefore = JsonConvert.SerializeObject(fixture.Manifest);

        // Le chiffrement et le JSON sont lisibles, mais l'affichage ou la generation
        // d'un code echoueraient si ce compte incomplet atteignait la fenetre principale.
        Check(fixture.Manifest.GetAllAccounts(fixture.Password).Length == 2,
            "Donnees incompletes decryptables sans erreur de mot de passe : " + defect);
        Throws<InvalidDataException>(() => fixture.Manifest.GetValidatedAccounts(fixture.Password),
            "Chargement refuse les donnees incompletes avant affichage des comptes : " + defect);
        AssertUnchanged(directory, before, fixture.Manifest, memoryBefore,
            "Refus des donnees incompletes preserve les fichiers pour recuperation : " + defect);
        Check(TransferBackup.ValidateRecovery(directory, fixture.Manifest, fixture.Account, fixture.Password),
            "Recuperation autorisee pour le compte dechiffrable mais incomplet : " + defect);
        TransferBackup.RecoverAccount(directory, fixture.Manifest, fixture.Account, fixture.Password);

        var restored = Manifest.LoadFromDirectory(directory).GetValidatedAccounts(fixture.Password);
        Check(restored.Length == 2 && restored[1].AccountName == fixture.Account.AccountName &&
            restored[1].Session.SteamID == fixture.Account.Session.SteamID &&
            restored[1].SharedSecret == fixture.Account.SharedSecret &&
            restored[1].IdentitySecret == fixture.Account.IdentitySecret,
            "Chargement complet possible apres restauration locale du compte : " + defect);
        Check(File.ReadAllBytes(fixture.TargetPath).SequenceEqual(before[Path.GetFileName(fixture.TargetPath)]) &&
            File.ReadAllBytes(Path.Combine(directory, fixture.Manifest.Entries[0].Filename))
                .SequenceEqual(before[fixture.Manifest.Entries[0].Filename]),
            "Fichier incomplet et autre compte conserves exactement : " + defect);
        AssertBackupIntact(fixture, before);
    }

    private static Fixture CreateFixture(string directory, int count, int targetIndex, bool changedPassword)
    {
        Directory.CreateDirectory(directory);
        var target = Account(targetIndex, 42);
        using var bytes = new MemoryStream();
        Serializer.Serialize(bytes, new CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response
        {
            success = true,
            replacement_token = new CRemoveAuthenticatorViaChallengeContinue_Replacement_Token
            {
                steamid = target.Session.SteamID, account_name = target.AccountName, status = 1,
                serial_number = 123, token_gid = "fictitious-token", uri = "fictitious-uri", server_time = 59,
                secret_1 = Convert.FromBase64String(target.Secret1),
                shared_secret = Convert.FromBase64String(target.SharedSecret),
                identity_secret = Convert.FromBase64String(target.IdentitySecret), revocation_code = target.RevocationCode
            }
        });
        var backup = new TransferBackup(directory, target.Session, BackupPassword);
        backup.Prepare();
        backup.SaveReply(new TransferReply { HttpStatus = 200, Result = 1, Body = bytes.ToArray() });
        var manifest = new Manifest
        {
            Encrypted = true, FirstRun = false, Entries = new List<Manifest.ManifestEntry>(),
            PeriodicChecking = true, PeriodicCheckingInterval = 17, CheckAllAccounts = true
        };
        for (var i = 0; i < count; i++)
        {
            var entry = new Manifest.ManifestEntry
            {
                SteamID = SteamId + (ulong)i, Filename = "fixture-" + i + ".maFile",
                Salt = FileEncryptor.GetRandomSalt(), IV = FileEncryptor.GetInitializationVector()
            };
            File.WriteAllText(Path.Combine(directory, entry.Filename), FileEncryptor.EncryptData(BackupPassword,
                entry.Salt, entry.IV, JsonConvert.SerializeObject(Account(i, (byte)(10 + i)))));
            manifest.Entries.Add(entry);
        }
        var indexPath = Path.Combine(directory, "manifest.json");
        File.WriteAllText(indexPath, JsonConvert.SerializeObject(manifest));
        manifest = Manifest.LoadFromDirectory(directory);
        if (changedPassword)
            Check(manifest.ChangeEncryptionKey(BackupPassword, CurrentPassword),
                "Preparation de comptes rechiffres apres creation de la sauvegarde");
        // Un BOM et un formatage distinct verifient une copie des octets, pas une reserialisation.
        File.WriteAllText(indexPath, JsonConvert.SerializeObject(manifest, Formatting.Indented), new UTF8Encoding(true));
        var opened = TransferBackup.Open(backup.FilePath, BackupPassword);
        return new Fixture
        {
            Manifest = manifest, Backup = backup,
            Account = AuthenticatorTransfer.ReadAccount(opened.Reply, opened.Session),
            TargetPath = Path.Combine(directory, manifest.Entries[targetIndex].Filename),
            Password = changedPassword ? CurrentPassword : BackupPassword
        };
    }

    private static SteamGuardAccount Account(int index, byte secret) => new SteamGuardAccount
    {
        AccountName = "fictitious-recovery-account-" + index,
        SharedSecret = Convert.ToBase64String(Enumerable.Repeat(secret, 20).ToArray()),
        IdentitySecret = Convert.ToBase64String(Enumerable.Repeat((byte)(secret + 1), 20).ToArray()),
        Secret1 = Convert.ToBase64String(Enumerable.Repeat((byte)(secret + 2), 20).ToArray()),
        RevocationCode = "R0000" + index, FullyEnrolled = true,
        Status = 1, SerialNumber = "123", TokenGID = "fictitious-token", URI = "fictitious-uri", ServerTime = 59,
        DeviceID = "android:" + Guid.NewGuid(),
        Session = new SessionData { SteamID = SteamId + (ulong)index, AccessToken = "fictitious-access", RefreshToken = "fictitious-refresh" }
    };

    private static Dictionary<string, byte[]> Snapshot(string directory) => Directory.GetFiles(directory)
        .ToDictionary(Path.GetFileName, File.ReadAllBytes);

    private static void AssertUnchanged(string directory, Dictionary<string, byte[]> before, Manifest manifest,
        string memoryBefore, string label)
    {
        var after = Snapshot(directory);
        Check(before.Count == after.Count && before.All(pair => after.TryGetValue(pair.Key, out var bytes) &&
            bytes.SequenceEqual(pair.Value)) && JsonConvert.SerializeObject(manifest) == memoryBefore, label);
    }

    private static void AssertBackupIntact(Fixture fixture, Dictionary<string, byte[]> before)
    {
        var opened = TransferBackup.Open(fixture.Backup.FilePath, BackupPassword);
        var account = AuthenticatorTransfer.ReadAccount(opened.Reply, opened.Session);
        Check(File.ReadAllBytes(fixture.Backup.FilePath).SequenceEqual(before[Path.GetFileName(fixture.Backup.FilePath)]) &&
            account.SharedSecret == fixture.Account.SharedSecret && account.IdentitySecret == fixture.Account.IdentitySecret,
            "Sauvegarde autonome intacte et toujours dechiffrable avec son mot de passe d'origine");
    }

    private sealed class Fixture
    {
        internal Manifest Manifest;
        internal TransferBackup Backup;
        internal SteamGuardAccount Account;
        internal string TargetPath;
        internal string Password;
    }

    private static void Throws<T>(Action action, string label) where T : Exception
    {
        try { action(); }
        catch (T) { Check(true, label); return; }
        throw new InvalidOperationException(label);
    }

    private static void ThrowsIo(Action action, string label)
    {
        try { action(); }
        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
        {
            Check(true, label);
            return;
        }
        throw new InvalidOperationException(label);
    }

    private static void Check(bool value, string label)
    {
        if (!value) throw new InvalidOperationException(label);
        checks++;
        Console.WriteLine("OK: " + label);
    }
}
