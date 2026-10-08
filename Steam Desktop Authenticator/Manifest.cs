using Newtonsoft.Json;
using SteamAuth;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Steam_Desktop_Authenticator
{
    public class Manifest
    {
        [JsonProperty("encrypted")]
        public bool Encrypted { get; set; }

        [JsonProperty("first_run")]
        public bool FirstRun { get; set; } = true;

        [JsonProperty("entries")]
        public List<ManifestEntry> Entries { get; set; }

        [JsonProperty("periodic_checking")]
        public bool PeriodicChecking { get; set; } = false;

        [JsonProperty("periodic_checking_interval")]
        public int PeriodicCheckingInterval { get; set; } = 5;

        [JsonProperty("periodic_checking_checkall")]
        public bool CheckAllAccounts { get; set; } = false;

        [JsonProperty("auto_confirm_market_transactions")]
        public bool AutoConfirmMarketTransactions { get; set; } = false;

        [JsonProperty("auto_confirm_trades")]
        public bool AutoConfirmTrades { get; set; } = false;

        private static Manifest _manifest { get; set; }

        // Lie chaque index a son dossier, y compris les dossiers fictifs des tests.
        internal string DataDirectory { get; private set; }
        internal bool NeedsRecovery { get; private set; }
        private string AccountDirectory => DataDirectory ?? Path.Combine(GetExecutableDir(), "maFiles");

        public static string GetExecutableDir()
        {
            return Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location);
        }

        public static Manifest GetManifest(bool forceLoad = false)
        {
            // Check if already staticly loaded
            if (_manifest != null && !forceLoad)
            {
                return _manifest;
            }

            _manifest = null;
            string maDir = Path.Combine(GetExecutableDir(), "maFiles");

            // If there's no config dir, create it
            if (!Directory.Exists(maDir))
            {
                _manifest = GenerateNewManifest(false);
                if (_manifest == null) throw new ManifestParseException();
                return _manifest;
            }

            // Ne mettre en cache qu'un index entierement valide.
            _manifest = LoadFromDirectory(maDir);
            return _manifest;
        }

        internal static Manifest LoadFromDirectory(string directory)
        {
            try
            {
                AccountStorageTransaction.Recover(directory);
                var manifest = JsonConvert.DeserializeObject<Manifest>(File.ReadAllText(Path.Combine(directory, "manifest.json")));
                if (manifest?.Entries == null || manifest.Entries.Any(e => e == null ||
                    string.IsNullOrWhiteSpace(e.Filename) || Path.GetFileName(e.Filename) != e.Filename))
                    throw new ManifestParseException();
                manifest.DataDirectory = directory;
                manifest.RecomputeExistingEntries();
                return manifest;
            }
            catch (Exception)
            {
                throw new ManifestParseException();
            }
        }

        internal static Manifest LoadForRecovery(string directory)
        {
            // Une reprise transactionnelle impossible ne doit pas etre confondue
            // avec un index absent puis ecrasee par une restauration de transfert.
            AccountStorageTransaction.Recover(directory);
            try { return LoadFromDirectory(directory); }
            catch (ManifestParseException)
            {
                // Aucun fichier n'est modifie avant la restauration effective.
                return new Manifest
                {
                    DataDirectory = directory, NeedsRecovery = true,
                    Entries = new List<ManifestEntry>()
                };
            }
        }

        internal void PreserveUnreadableManifest()
        {
            if (!NeedsRecovery) return;
            var path = Path.Combine(AccountDirectory, "manifest.json");
            if (File.Exists(path))
                File.Copy(path, path + ".unreadable-" + Guid.NewGuid().ToString("N") + ".bak", false);
        }

        internal void CompleteRecovery() => NeedsRecovery = false;

        public static Manifest GenerateNewManifest(bool scanDir = false)
        {
            // No directory means no manifest file anyways.
            Manifest newManifest = new Manifest();
            newManifest.Encrypted = false;
            newManifest.PeriodicCheckingInterval = 5;
            newManifest.PeriodicChecking = false;
            newManifest.AutoConfirmMarketTransactions = false;
            newManifest.AutoConfirmTrades = false;
            newManifest.Entries = new List<ManifestEntry>();
            newManifest.FirstRun = true;

            // Take a pre-manifest version and generate a manifest for it.
            if (scanDir)
            {
                string maDir = Manifest.GetExecutableDir() + "/maFiles/";
                if (Directory.Exists(maDir))
                {
                    DirectoryInfo dir = new DirectoryInfo(maDir);
                    var files = dir.GetFiles();

                    foreach (var file in files)
                    {
                        if (file.Extension != ".maFile") continue;

                        string contents = File.ReadAllText(file.FullName);
                        try
                        {
                            SteamGuardAccount account = JsonConvert.DeserializeObject<SteamGuardAccount>(contents);
                            ManifestEntry newEntry = new ManifestEntry()
                            {
                                Filename = file.Name,
                                SteamID = account.Session.SteamID
                            };
                            newManifest.Entries.Add(newEntry);
                        }
                        catch (Exception)
                        {
                            throw new MaFileEncryptedException();
                        }
                    }

                    if (newManifest.Entries.Count > 0)
                    {
                        newManifest.Save();
                        newManifest.PromptSetupPassKey("This version of SDA has encryption. Please enter a passkey below, or hit cancel to remain unencrypted");
                    }
                }
            }

            if (newManifest.Save())
            {
                return newManifest;
            }

            return null;
        }

        public class IncorrectPassKeyException : Exception { }
        public class ManifestNotEncryptedException : Exception { }

        public string PromptForPassKey()
        {
            if (!this.Encrypted)
            {
                throw new ManifestNotEncryptedException();
            }

            bool passKeyValid = false;
            string passKey = null;
            while (!passKeyValid)
            {
                InputForm passKeyForm = new InputForm("Please enter your encryption passkey.", true);
                passKeyForm.ShowDialog();
                if (!passKeyForm.Canceled)
                {
                    passKey = passKeyForm.txtBox.Text;
                    passKeyValid = this.VerifyPasskey(passKey);
                    if (!passKeyValid)
                    {
                        MessageBox.Show("That passkey is invalid.");
                    }
                }
                else
                {
                    return null;
                }
            }
            return passKey;
        }

        public string PromptSetupPassKey(string initialPrompt = "Enter passkey, or hit cancel to remain unencrypted.")
        {
            InputForm newPassKeyForm = new InputForm(initialPrompt);
            newPassKeyForm.ShowDialog();
            if (newPassKeyForm.Canceled || newPassKeyForm.txtBox.Text.Length == 0)
            {
                MessageBox.Show("WARNING: You chose to not encrypt your files. Doing so imposes a security risk for yourself. If an attacker were to gain access to your computer, they could completely lock you out of your account and steal all your items.");
                return null;
            }

            InputForm newPassKeyForm2 = new InputForm("Confirm new passkey.");
            newPassKeyForm2.ShowDialog();
            if (newPassKeyForm2.Canceled)
            {
                MessageBox.Show("WARNING: You chose to not encrypt your files. Doing so imposes a security risk for yourself. If an attacker were to gain access to your computer, they could completely lock you out of your account and steal all your items.");
                return null;
            }

            string newPassKey = newPassKeyForm.txtBox.Text;
            string confirmPassKey = newPassKeyForm2.txtBox.Text;

            if (newPassKey != confirmPassKey)
            {
                MessageBox.Show("Passkeys do not match.");
                return null;
            }

            if (!this.ChangeEncryptionKey(null, newPassKey))
            {
                MessageBox.Show("Unable to set passkey.");
                return null;
            }
            else
            {
                MessageBox.Show("Passkey successfully set.");
            }

            return newPassKey;
        }

        public SteamAuth.SteamGuardAccount[] GetAllAccounts(string passKey = null, int limit = -1)
        {
            if (AccountStorageTransaction.IsPending(AccountDirectory))
                throw new InvalidDataException("An interrupted account update must be recovered before reading accounts.");
            if (passKey == null && this.Encrypted) return new SteamGuardAccount[0];
            string maDir = AccountDirectory + Path.DirectorySeparatorChar;

            List<SteamAuth.SteamGuardAccount> accounts = new List<SteamAuth.SteamGuardAccount>();
            foreach (var entry in this.Entries)
            {
                string fileText = File.ReadAllText(maDir + entry.Filename);
                if (this.Encrypted)
                {
                    string decryptedText = FileEncryptor.DecryptData(passKey, entry.Salt, entry.IV, fileText);
                    if (decryptedText == null) return new SteamGuardAccount[0];
                    fileText = decryptedText;
                }

                var account = JsonConvert.DeserializeObject<SteamAuth.SteamGuardAccount>(fileText);
                if (account == null) continue;
                accounts.Add(account);

                if (limit != -1 && limit >= accounts.Count)
                    break;
            }

            return accounts.ToArray();
        }

        public bool ChangeEncryptionKey(string oldKey, string newKey)
        {
            try
            {
                if (AccountStorageTransaction.IsPending(AccountDirectory)) return false;
                GetValidatedAccounts(oldKey);
                bool toEncrypt = newKey != null;
                if (toEncrypt && newKey.Length == 0) return false;
                var next = JsonConvert.DeserializeObject<Manifest>(JsonConvert.SerializeObject(this));
                var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    for (int i = 0; i < next.Entries.Count; i++)
                    {
                        var entry = next.Entries[i];
                        // Conserver aussi les champs inconnus et le formatage du
                        // maFile : un changement de mot de passe ne doit pas les perdre.
                        var contents = File.ReadAllText(Path.Combine(AccountDirectory, entry.Filename));
                        if (Encrypted)
                            contents = FileEncryptor.DecryptData(oldKey, Entries[i].Salt, Entries[i].IV, contents);
                        if (!IsUsableAccount(JsonConvert.DeserializeObject<SteamGuardAccount>(contents), entry.SteamID))
                            return false;
                        entry.Salt = toEncrypt ? FileEncryptor.GetRandomSalt() : null;
                        entry.IV = toEncrypt ? FileEncryptor.GetInitializationVector() : null;
                        if (toEncrypt)
                            contents = FileEncryptor.EncryptData(newKey, entry.Salt, entry.IV, contents);
                        files.Add(entry.Filename, Encoding.UTF8.GetBytes(contents));
                    }
                    next.Encrypted = toEncrypt;
                    AccountStorageTransaction.Commit(AccountDirectory, files,
                        Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(next)));
                    Entries = next.Entries;
                    Encrypted = next.Encrypted;
                    return true;
                }
                finally
                {
                    foreach (var bytes in files.Values)
                        System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
                }
            }
            catch (Exception) { return false; }
        }

        public bool VerifyPasskey(string passkey)
        {
            if (!this.Encrypted || this.Entries.Count == 0) return true;

            var accounts = this.GetAllAccounts(passkey, 1);
            return accounts != null && accounts.Length == 1;
        }

        internal static bool IsUsableAccount(SteamGuardAccount account, ulong steamId)
        {
            try
            {
                return steamId != 0 && account?.Session?.SteamID == steamId &&
                    !string.IsNullOrWhiteSpace(account.AccountName) &&
                    !string.IsNullOrWhiteSpace(account.SharedSecret) &&
                    !string.IsNullOrWhiteSpace(account.IdentitySecret) &&
                    Convert.FromBase64String(account.SharedSecret).Length > 0 &&
                    Convert.FromBase64String(account.IdentitySecret).Length > 0;
            }
            catch (FormatException) { return false; }
        }

        internal SteamGuardAccount[] GetValidatedAccounts(string passphrase)
        {
            if (Entries.Select(entry => entry.SteamID).Distinct().Count() != Entries.Count ||
                Entries.Select(entry => entry.Filename).Distinct(StringComparer.OrdinalIgnoreCase).Count() != Entries.Count)
                throw new InvalidDataException("SDA account entries must be unique.");
            var accounts = GetAllAccounts(passphrase);
            if (accounts.Length != Entries.Count ||
                accounts.Where((account, index) => !IsUsableAccount(account, Entries[index].SteamID)).Any())
                throw new InvalidDataException("SDA could not unlock complete account data. Use the current encryption password or Recover saved transfer.");
            return accounts;
        }

        public bool RemoveAccount(SteamGuardAccount account, bool deleteMaFile = true)
        {
            ManifestEntry entry = (from e in this.Entries where e.SteamID == account.Session.SteamID select e).FirstOrDefault();
            if (entry == null) return true; // If something never existed, did you do what they asked?

            string maDir = AccountDirectory + Path.DirectorySeparatorChar;
            string filename = maDir + entry.Filename;
            this.Entries.Remove(entry);

            if (this.Entries.Count == 0)
            {
                this.Encrypted = false;
            }

            if (this.Save() && deleteMaFile)
            {
                try
                {
                    File.Delete(filename);
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }

            return false;
        }

        public bool SaveAccount(SteamGuardAccount account, bool encrypt, string passKey = null)
        {
            if (encrypt && String.IsNullOrEmpty(passKey)) return false;
            if (!encrypt && this.Encrypted) return false;
            try
            {
                if (AccountStorageTransaction.IsPending(AccountDirectory) ||
                    !IsUsableAccount(account, account?.Session?.SteamID ?? 0)) return false;
                GetValidatedAccounts(passKey);
                // Ajouter un compte chiffre ne doit pas changer le flag d'anciens
                // comptes en clair sans les chiffrer eux aussi.
                if (encrypt && !Encrypted && Entries.Count != 0) return false;
                var next = JsonConvert.DeserializeObject<Manifest>(JsonConvert.SerializeObject(this));
                var index = next.Entries.FindIndex(entry => entry.SteamID == account.Session.SteamID);
                var filename = index >= 0 ? next.Entries[index].Filename : account.Session.SteamID + ".maFile";
                if (index < 0 && File.Exists(Path.Combine(AccountDirectory, filename)))
                    filename = account.Session.SteamID + "-" + Guid.NewGuid().ToString("N") + ".maFile";
                var entry = new ManifestEntry
                {
                    SteamID = account.Session.SteamID, Filename = filename,
                    Salt = encrypt ? FileEncryptor.GetRandomSalt() : null,
                    IV = encrypt ? FileEncryptor.GetInitializationVector() : null
                };
                var contents = JsonConvert.SerializeObject(account);
                if (encrypt) contents = FileEncryptor.EncryptData(passKey, entry.Salt, entry.IV, contents);
                if (index >= 0) next.Entries[index] = entry;
                else next.Entries.Add(entry);
                next.Encrypted = encrypt || Encrypted;
                var bytes = Encoding.UTF8.GetBytes(contents);
                try
                {
                    AccountStorageTransaction.Commit(AccountDirectory, new Dictionary<string, byte[]> { [filename] = bytes },
                        Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(next)));
                }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
                Entries = next.Entries;
                Encrypted = next.Encrypted;
                return true;
            }
            catch (Exception) { return false; }
        }

        public bool Save()
        {
            if (AccountStorageTransaction.IsPending(AccountDirectory)) return false;
            string maDir = AccountDirectory + Path.DirectorySeparatorChar;
            string filename = maDir + "manifest.json";
            if (!Directory.Exists(maDir))
            {
                try
                {
                    Directory.CreateDirectory(maDir);
                }
                catch (Exception)
                {
                    return false;
                }
            }

            try
            {
                string contents = JsonConvert.SerializeObject(this);
                AccountStorageTransaction.WriteAtomic(filename, Encoding.UTF8.GetBytes(contents), true);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private void RecomputeExistingEntries()
        {
            List<ManifestEntry> newEntries = new List<ManifestEntry>();
            string maDir = AccountDirectory + Path.DirectorySeparatorChar;

            foreach (var entry in this.Entries)
            {
                string filename = maDir + entry.Filename;
                if (File.Exists(filename))
                {
                    newEntries.Add(entry);
                }
            }

            this.Entries = newEntries;

            if (this.Entries.Count == 0)
            {
                this.Encrypted = false;
            }
        }

        public void MoveEntry(int from, int to)
        {
            if (from < 0 || to < 0 || from > Entries.Count || to > Entries.Count - 1) return;
            ManifestEntry sel = Entries[from];
            Entries.RemoveAt(from);
            Entries.Insert(to, sel);
            Save();
        }

        public class ManifestEntry
        {
            [JsonProperty("encryption_iv")]
            public string IV { get; set; }

            [JsonProperty("encryption_salt")]
            public string Salt { get; set; }

            [JsonProperty("filename")]
            public string Filename { get; set; }

            [JsonProperty("steamid")]
            public ulong SteamID { get; set; }
        }
    }
}
