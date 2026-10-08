using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using Newtonsoft.Json;
using ProtoBuf;
using SteamAuth;
using SteamKit2.Internal;
using Steam_Desktop_Authenticator;

internal static class ManifestChecks
{
    private static int checks;
    private const string Password = "mot-de-passe-fictif-manifest";

    internal static int Run()
    {
        var root = Path.Combine(Path.GetTempPath(), "sda-manifest-checks-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            ReconnectAndEncryption(Path.Combine(root, "reconnect"));
            foreach (var content in new[] { null, "invalid-json", "null", "{}", "{\"entries\":[null]}" })
                RecoverMissingIndex(Path.Combine(root, Guid.NewGuid().ToString("N")), content);
            RecoveryWriteFailure(Path.Combine(root, "write-failure"));
            using var form = new TransferAuthenticatorForm(recoveryOnly: true);
            var buttons = form.Controls[0].Controls.OfType<Button>().ToArray();
            Check(form.Text == "Recover saved transfer" &&
                !buttons.Single(b => b.Text == "Sign in and transfer").Enabled &&
                buttons.Single(b => b.Text == "Recover saved transfer").Enabled,
                "Ecran de recuperation disponible sans autoriser de nouveau transfert");
            return checks;
        }
        finally
        {
            // Exclusivement le dossier aleatoire de donnees fictives cree ci-dessus.
            Directory.Delete(root, true);
        }
    }

    private static TransferBackup Fixture(string directory)
    {
        var session = new SessionData { SteamID = 76561198000000000, AccessToken = "fictitious-access" };
        using var bytes = new MemoryStream();
        Serializer.Serialize(bytes, new CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response
        {
            success = true,
            replacement_token = new CRemoveAuthenticatorViaChallengeContinue_Replacement_Token
            {
                steamid = session.SteamID, account_name = "fictitious-account", status = 1,
                shared_secret = Encoding.ASCII.GetBytes("12345678901234567890"),
                identity_secret = new byte[20], revocation_code = "R00000"
            }
        });
        var backup = new TransferBackup(directory, session, Password);
        backup.Prepare();
        backup.SaveReply(new TransferReply { HttpStatus = 200, Result = 1, Body = bytes.ToArray() });
        return backup;
    }

    private static void ReconnectAndEncryption(string directory)
    {
        var backup = Fixture(directory);
        var account = AuthenticatorTransfer.ReadAccount(backup.Reply, backup.Session);
        var manifest = Manifest.LoadForRecovery(directory);
        TransferBackup.SaveAccount(directory, manifest, account, Password);
        manifest = Manifest.LoadFromDirectory(directory);
        var original = manifest.Entries.Single().Filename;
        Check(manifest.ChangeEncryptionKey(Password, null), "Dechiffrement du compte transfere pour export");
        Check(manifest.SaveAccount(account, false), "Sauvegarde apres reconnexion du compte dechiffre");
        Check(manifest.Entries.Single().Filename == original, "Reconnexion conserve le nom du maFile de transfert");
        Check(manifest.ChangeEncryptionKey(null, Password), "Rechiffrement apres export et reconnexion");
        Check(Directory.GetFiles(directory, "*.maFile").Length == 1 &&
            !File.ReadAllText(Path.Combine(directory, original)).Contains("shared_secret"),
            "Aucun maFile orphelin en clair apres rechiffrement");
        manifest = Manifest.LoadFromDirectory(directory);
        Check(manifest.GetAllAccounts(Password).Single().SharedSecret == account.SharedSecret,
            "Secrets lisibles apres rechargement du compte rechiffre");
        Check(manifest.SaveAccount(account, true, Password), "Reconnexion du compte chiffre");
        Check(manifest.Entries.Single().Filename == original && Directory.GetFiles(directory, "*.maFile").Length == 1,
            "Reconnexion chiffree ne cree pas non plus de fichier orphelin");
        Check(Manifest.LoadFromDirectory(directory).GetAllAccounts(Password).Single().IdentitySecret == account.IdentitySecret,
            "Secret de confirmation conserve apres reconnexion chiffree");
        var before = File.ReadAllText(Path.Combine(directory, "manifest.json"));
        var existing = Manifest.LoadForRecovery(directory);
        Check(!existing.NeedsRecovery && existing.Entries.Count == 1 &&
            File.ReadAllText(Path.Combine(directory, "manifest.json")) == before,
            "Un index valide est reutilise sans reinitialisation");
    }

    private static void RecoverMissingIndex(string directory, string content)
    {
        var backup = Fixture(directory);
        var index = Path.Combine(directory, "manifest.json");
        var otherFile = Path.Combine(directory, "other-account.maFile");
        File.WriteAllText(otherFile, "fictitious-encrypted-account");
        if (content != null) File.WriteAllText(index, content);
        bool failed = false;
        try { Manifest.LoadFromDirectory(directory); }
        catch (ManifestParseException) { failed = true; }
        Check(failed, "Index absent ou invalide declenche le parcours de recuperation");
        var filesBefore = Directory.GetFiles(directory).OrderBy(p => p).ToArray();
        var manifest = Manifest.LoadForRecovery(directory);
        Check(manifest.NeedsRecovery && manifest.Entries.Count == 0 &&
            Directory.GetFiles(directory).OrderBy(p => p).SequenceEqual(filesBefore) &&
            (content == null ? !File.Exists(index) : File.ReadAllText(index) == content),
            "Ouverture puis annulation de la recuperation ne modifie aucun fichier");
        bool wrongPassword = false;
        try { TransferBackup.Open(backup.FilePath, "wrong-password"); }
        catch (System.Security.Cryptography.CryptographicException) { wrongPassword = true; }
        Check(wrongPassword && (content == null ? !File.Exists(index) : File.ReadAllText(index) == content),
            "Mauvais mot de passe ne remplace pas l'index");
        var restored = TransferBackup.Open(backup.FilePath, Password);
        var account = AuthenticatorTransfer.ReadAccount(restored.Reply, restored.Session);
        TransferBackup.SaveAccount(directory, manifest, account, Password);
        var reloaded = Manifest.LoadFromDirectory(directory);
        Check(!manifest.NeedsRecovery && reloaded.Encrypted &&
            reloaded.GetAllAccounts(Password).Single().SharedSecret == account.SharedSecret,
            "Recuperation hors ligne cree un index chiffre utilisable au redemarrage");
        var preserved = Directory.GetFiles(directory, "manifest.json.unreadable-*.bak");
        Check(content == null ? preserved.Length == 0 : preserved.Length == 1 && File.ReadAllText(preserved[0]) == content,
            "Index illisible conserve exactement avant son remplacement");
        Check(File.ReadAllText(otherFile) == "fictitious-encrypted-account" &&
            TransferBackup.Open(backup.FilePath, Password).Reply.Body.SequenceEqual(backup.Reply.Body),
            "Autres comptes et sauvegarde de transfert preserves");
    }

    private static void RecoveryWriteFailure(string directory)
    {
        var backup = Fixture(directory);
        var index = Path.Combine(directory, "manifest.json");
        File.WriteAllText(index, "damaged-index");
        var manifest = Manifest.LoadForRecovery(directory);
        var account = AuthenticatorTransfer.ReadAccount(backup.Reply, backup.Session);
        bool failed = false;
        using (var locked = new FileStream(index, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            try { TransferBackup.SaveAccount(directory, manifest, account, Password); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { failed = true; }
        }
        Check(failed && manifest.NeedsRecovery && manifest.Entries.Count == 0 && File.ReadAllText(index) == "damaged-index",
            "Echec de remplacement preserve l'index et l'etat de recuperation");
        TransferBackup.SaveAccount(directory, manifest, account, Password);
        Check(Manifest.LoadFromDirectory(directory).GetAllAccounts(Password).Length == 1,
            "Recuperation relancable localement apres echec d'ecriture");
        Check(Directory.GetFiles(directory, "*.maFile").All(p => !File.ReadAllText(p).Contains("shared_secret")),
            "Fichiers conserves apres echec de recuperation tous chiffres");
    }

    private static void Check(bool value, string label)
    {
        if (!value) throw new InvalidOperationException(label);
        checks++;
        Console.WriteLine("OK: " + label);
    }
}
