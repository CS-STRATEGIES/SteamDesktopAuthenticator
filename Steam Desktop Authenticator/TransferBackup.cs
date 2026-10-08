using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using SteamAuth;

namespace Steam_Desktop_Authenticator
{
    // Sauvegarde autonome, authentifiee, recuperable meme si le manifest est absent.
    // Le mot de passe n'est jamais stocke. Les maFiles restent au format SDA historique.
    internal sealed class TransferBackup
    {
        private const int Iterations = 600000;
        private const string Format = "SDA-transfer-v1";
        private readonly string passphrase;
        internal string FilePath { get; set; }
        internal SessionData Session { get; }
        internal TransferReply Reply { get; private set; }

        internal TransferBackup(string directory, SessionData session, string passphrase)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(passphrase);
            Directory.CreateDirectory(directory);
            FilePath = Path.Combine(directory, "transfer-" + Guid.NewGuid().ToString("N") + ".sda-transfer");
            Session = session;
            this.passphrase = passphrase;
        }

        internal void Prepare()
        {
            Save();
            // Tester le chemin ET le chiffrement avant de demander le remplacement.
            var check = Open(FilePath, passphrase);
            if (check.Session.SteamID != Session.SteamID)
                throw new IOException("Unable to verify the encrypted recovery backup.");
        }

        internal void SaveReply(TransferReply reply)
        {
            Reply = reply;
            Save();
        }

        internal void MarkSubmitting()
        {
            // Un second SMS apres refus explicite ne doit pas laisser l'ancienne
            // reponse etre confondue avec le resultat de la nouvelle tentative.
            Reply = null;
            Save();
        }

        private void Save()
        {
            var salt = RandomNumberGenerator.GetBytes(16);
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var plaintext = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new BackupData { Session = Session, Reply = Reply }));
            var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, Iterations, HashAlgorithmName.SHA256, 32);
            try
            {
                var ciphertext = new byte[plaintext.Length];
                using var aes = new AesGcm(key, tag.Length);
                aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(Format));
                WriteAtomic(FilePath, JsonConvert.SerializeObject(new Envelope
                {
                    Format = Format, Salt = salt, Nonce = nonce, Tag = tag, Ciphertext = ciphertext
                }));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        internal static TransferBackup Open(string path, string passphrase)
        {
            if (new FileInfo(path).Length > 1024 * 1024)
                throw new InvalidDataException("Invalid transfer backup.");
            var envelope = JsonConvert.DeserializeObject<Envelope>(File.ReadAllText(path));
            if (envelope?.Format != Format || envelope.Salt?.Length != 16 ||
                envelope.Nonce?.Length != 12 || envelope.Tag?.Length != 16 || envelope.Ciphertext == null)
                throw new InvalidDataException("Invalid transfer backup.");
            var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, envelope.Salt, Iterations, HashAlgorithmName.SHA256, 32);
            var plaintext = new byte[envelope.Ciphertext.Length];
            try
            {
                using var aes = new AesGcm(key, 16);
                aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext, Encoding.UTF8.GetBytes(Format));
                var data = JsonConvert.DeserializeObject<BackupData>(Encoding.UTF8.GetString(plaintext));
                if (data?.Session == null || data.Session.SteamID == 0)
                    throw new InvalidDataException("Invalid transfer backup.");
                return new TransferBackup(Path.GetDirectoryName(Path.GetFullPath(path)), data.Session, passphrase)
                {
                    FilePath = path, Reply = data.Reply
                };
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        internal static void SaveAccount(string directory, Manifest manifest, SteamGuardAccount account, string passphrase)
        {
            if (manifest.Entries.Any(e => e.SteamID == account.Session.SteamID))
                throw new InvalidOperationException("This account already exists in SDA. No file was overwritten.");
            if (!manifest.Encrypted && manifest.Entries.Count != 0)
                throw new InvalidOperationException("Enable encryption for existing accounts before importing this transfer.");
            SaveAccountCore(directory, manifest, account, passphrase);
        }

        internal static bool ValidateRecovery(string directory, Manifest manifest, SteamGuardAccount account, string passphrase)
        {
            RequireCompletedStorageUpdate(directory);
            ArgumentException.ThrowIfNullOrWhiteSpace(passphrase);
            var matching = manifest.Entries.Where(e => e.SteamID == account.Session.SteamID).ToArray();
            if (matching.Length > 1)
                throw new InvalidOperationException("The account index contains duplicate entries. Restore your complete maFiles backup.");
            foreach (var entry in manifest.Entries.Where(e => e.SteamID != account.Session.SteamID))
            {
                if (!manifest.Encrypted || !CanReadAccount(directory, manifest, entry, passphrase))
                    throw new InvalidOperationException("The other SDA accounts cannot all be unlocked with this password. Use their current SDA encryption password or restore your complete maFiles backup. No account was changed.");
            }
            if (matching.Length == 0) return false;
            if (CanReadAccount(directory, manifest, matching[0], passphrase))
                throw new InvalidOperationException("This account is already readable in SDA. Recovery will not replace it with a possibly older authenticator.");
            // Le format CBC ne distingue pas toujours corruption et mauvais mot de passe.
            // Le formulaire exige une confirmation avant ce remplacement local reversible.
            return true;
        }

        private static bool CanReadAccount(string directory, Manifest manifest, Manifest.ManifestEntry entry, string passphrase)
        {
            // Les erreurs d'acces et d'E/S restent des erreurs : elles ne prouvent pas
            // une corruption et ne doivent jamais autoriser le remplacement du compte.
            var text = File.ReadAllText(Path.Combine(directory, entry.Filename));
            try
            {
                if (manifest.Encrypted)
                    text = FileEncryptor.DecryptData(passphrase, entry.Salt, entry.IV, text);
                if (string.IsNullOrWhiteSpace(text)) return false;
                var account = JsonConvert.DeserializeObject<SteamGuardAccount>(text);
                return Manifest.IsUsableAccount(account, entry.SteamID);
            }
            catch (Exception ex) when (ex is JsonException || ex is FormatException ||
                ex is CryptographicException || ex is ArgumentException)
            {
                return false;
            }
        }

        internal static void RecoverAccount(string directory, Manifest manifest, SteamGuardAccount account, string passphrase)
        {
            var replacing = ValidateRecovery(directory, manifest, account, passphrase);
            var index = replacing ? manifest.Entries.FindIndex(e => e.SteamID == account.Session.SteamID) : -1;
            SaveAccountCore(directory, manifest, account, passphrase, index);
        }

        private static void SaveAccountCore(string directory, Manifest manifest, SteamGuardAccount account, string passphrase, int replaceIndex = -1)
        {
            RequireCompletedStorageUpdate(directory);
            ArgumentException.ThrowIfNullOrWhiteSpace(passphrase);
            var salt = FileEncryptor.GetRandomSalt();
            var iv = FileEncryptor.GetInitializationVector();
            var encrypted = FileEncryptor.EncryptData(passphrase, salt, iv, JsonConvert.SerializeObject(account));
            if (encrypted == null) throw new IOException("Unable to encrypt the account.");

            // Un nom unique permet de recuperer apres un echec du manifest sans ecraser
            // un maFile orphelin. Les rafraichissements suivants conservent ce nom.
            var filename = account.Session.SteamID + "-" + Guid.NewGuid().ToString("N") + ".maFile";
            var next = JsonConvert.DeserializeObject<Manifest>(JsonConvert.SerializeObject(manifest));
            next.Encrypted = true;
            var entry = new Manifest.ManifestEntry
            {
                SteamID = account.Session.SteamID, Filename = filename, Salt = salt, IV = iv
            };
            if (replaceIndex >= 0)
            {
                next.Entries[replaceIndex] = entry;
                // Conserver aussi les anciens IV/sel : le maFile d'origine reste intact.
                // Un echec de cette copie doit arreter la restauration avant mutation.
                var indexPath = Path.Combine(directory, "manifest.json");
                File.Copy(indexPath, indexPath + ".before-recovery-" + Guid.NewGuid().ToString("N") + ".bak", false);
            }
            else next.Entries.Add(entry);
            WriteAtomic(Path.Combine(directory, filename), encrypted);
            // Si cette copie echoue, ne pas remplacer l'index endommage.
            manifest.PreserveUnreadableManifest();
            WriteAtomic(Path.Combine(directory, "manifest.json"), JsonConvert.SerializeObject(next));
            manifest.Entries = next.Entries;
            manifest.Encrypted = true;
            manifest.CompleteRecovery();
        }

        private static void RequireCompletedStorageUpdate(string directory)
        {
            if (AccountStorageTransaction.IsPending(directory))
                throw new IOException("Restart SDA to recover the interrupted account update before importing a transfer.");
        }

        internal static void WriteAtomic(string path, string text)
        {
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    var bytes = Encoding.UTF8.GetBytes(text);
                    file.Write(bytes);
                    file.Flush(true);
                }
                File.Move(temporary, path, true);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        private sealed class BackupData
        {
            public SessionData Session { get; set; }
            public TransferReply Reply { get; set; }
        }

        private sealed class Envelope
        {
            public string Format { get; set; }
            public byte[] Salt { get; set; }
            public byte[] Nonce { get; set; }
            public byte[] Tag { get; set; }
            public byte[] Ciphertext { get; set; }
        }
    }
}
