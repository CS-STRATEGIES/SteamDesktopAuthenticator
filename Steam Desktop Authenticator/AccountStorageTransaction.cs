using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Steam_Desktop_Authenticator
{
    // Un journal chiffre permet de restaurer les anciens octets apres une erreur
    // ou une interruption. Aucun ancien maFile en clair n'est copie sur disque.
    internal static class AccountStorageTransaction
    {
        private const string JournalName = ".sda-storage-transaction";
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SDA-account-storage-v1");
        // Injection reservee aux controles hors ligne, sans acces aux donnees.
        internal static Action<int> AfterAccountWrite { get; set; }

        internal static bool IsPending(string directory) => File.Exists(Path.Combine(directory, JournalName));

        internal static void Commit(string directory, Dictionary<string, byte[]> files, byte[] manifest)
        {
            if (IsPending(directory))
                throw new IOException("An interrupted account update must be recovered before another update.");
            if (files.Keys.Distinct(StringComparer.OrdinalIgnoreCase).Count() != files.Count)
                throw new InvalidDataException("Account filenames must be unique.");
            var snapshot = new Snapshot { ManifestTemporaryName = NewTemporaryName() };
            var handles = new List<FileStream>();
            var changed = new List<StoredFile>();
            bool manifestChanged = false;
            bool journalWritten = false;
            try
            {
                // Ouvrir tous les fichiers avant mutation : un verrou ou un fichier
                // non inscriptible doit echouer sans toucher les autres comptes.
                snapshot.Manifest = ReadLocked(Path.Combine(directory, "manifest.json"), handles);
                foreach (var pair in files)
                {
                    ValidateName(pair.Key);
                    snapshot.Files.Add(new StoredFile
                    {
                        Name = pair.Key,
                        TemporaryName = NewTemporaryName(),
                        Content = ReadLocked(Path.Combine(directory, pair.Key), handles)
                    });
                }
                var serialized = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(snapshot));
                try
                {
                    var protectedBytes = ProtectedData.Protect(serialized, Entropy, DataProtectionScope.CurrentUser);
                    WriteAtomic(Path.Combine(directory, JournalName), protectedBytes, false);
                    journalWritten = true;
                }
                finally { CryptographicOperations.ZeroMemory(serialized); }

                // Les controles d'acces sont termines. Windows peut refuser un
                // remplacement quand la destination reste ouverte ; le journal
                // durable assure desormais le rollback des octets controles.
                foreach (var handle in handles) handle.Dispose();
                handles.Clear();

                foreach (var original in snapshot.Files)
                {
                    // Replace peut signaler une erreur de metadonnees apres une
                    // mutation partielle : restaurer aussi la cible de la tentative.
                    if (original.Content != null) changed.Add(original);
                    WriteAtomic(Path.Combine(directory, original.Name), files[original.Name], original.Content != null,
                        Path.Combine(directory, original.TemporaryName));
                    if (original.Content == null) changed.Add(original);
                    AfterAccountWrite?.Invoke(changed.Count);
                }
                manifestChanged = snapshot.Manifest != null;
                WriteAtomic(Path.Combine(directory, "manifest.json"), manifest, snapshot.Manifest != null,
                    Path.Combine(directory, snapshot.ManifestTemporaryName));
                manifestChanged = true;
                // Le journal est le marqueur de transaction : tant qu'il existe,
                // les lectures et nouvelles ecritures sont bloquees. Le chargement
                // restaure exactement l'index et les seuls fichiers de cette
                // operation avant d'autoriser un autre enregistrement ou transfert.
                File.Delete(Path.Combine(directory, JournalName));
                journalWritten = false;
            }
            catch
            {
                if (journalWritten)
                {
                    // En cas d'echec du rollback, conserver le journal pour que le
                    // chargement refuse des donnees incoherentes et retente la reprise.
                    Restore(directory, snapshot, changed, manifestChanged);
                    foreach (var file in snapshot.Files)
                        File.Delete(Path.Combine(directory, file.TemporaryName));
                    File.Delete(Path.Combine(directory, snapshot.ManifestTemporaryName));
                    File.Delete(Path.Combine(directory, JournalName));
                }
                throw;
            }
            finally
            {
                foreach (var handle in handles) handle.Dispose();
                Clear(snapshot);
            }
        }

        internal static void Recover(string directory)
        {
            var path = Path.Combine(directory, JournalName);
            if (!File.Exists(path)) return;
            var plaintext = ProtectedData.Unprotect(File.ReadAllBytes(path), Entropy, DataProtectionScope.CurrentUser);
            Snapshot snapshot = null;
            try
            {
                snapshot = JsonConvert.DeserializeObject<Snapshot>(Encoding.UTF8.GetString(plaintext));
                if (snapshot?.Files == null || snapshot.Files.Any(file => file == null) ||
                    snapshot.Files.Select(file => file.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != snapshot.Files.Count)
                    throw new InvalidDataException("Invalid account recovery journal.");
                foreach (var file in snapshot.Files) ValidateName(file.Name);
                var temporaryNames = snapshot.Files.Select(file => file.TemporaryName)
                    .Append(snapshot.ManifestTemporaryName).ToArray();
                if (temporaryNames.Any(name => string.IsNullOrWhiteSpace(name) || Path.GetFileName(name) != name ||
                    name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                    !name.StartsWith(".sda-write-", StringComparison.Ordinal) || !name.EndsWith(".tmp", StringComparison.Ordinal)) ||
                    temporaryNames.Distinct(StringComparer.OrdinalIgnoreCase).Count() != temporaryNames.Length)
                    throw new InvalidDataException("Invalid account recovery journal.");
                // Une interruption peut laisser un staging en clair lors d'un export.
                // Ses noms sont authentifies et strictement bornes par le journal.
                foreach (var name in temporaryNames) File.Delete(Path.Combine(directory, name));
                Restore(directory, snapshot, snapshot.Files, true);
                File.Delete(path);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                if (snapshot != null) Clear(snapshot);
            }
        }

        private static byte[] ReadLocked(string path, List<FileStream> handles)
        {
            if (!File.Exists(path)) return null;
            // Les lecteurs restent possibles pendant le controle, pas les auteurs.
            var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read | FileShare.Delete);
            handles.Add(stream);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            return copy.ToArray();
        }

        private static void Restore(string directory, Snapshot snapshot, IEnumerable<StoredFile> files, bool restoreManifest)
        {
            foreach (var file in files)
                RestoreFile(Path.Combine(directory, file.Name), file.Content, Path.Combine(directory, file.TemporaryName));
            if (restoreManifest)
                RestoreFile(Path.Combine(directory, "manifest.json"), snapshot.Manifest, Path.Combine(directory, snapshot.ManifestTemporaryName));
        }

        private static void RestoreFile(string path, byte[] content, string temporary)
        {
            if (content == null) File.Delete(path);
            else WriteAtomic(path, content, true, temporary);
        }

        internal static void WriteAtomic(string path, byte[] content, bool overwrite, string temporary = null)
        {
            temporary ??= path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(content);
                    stream.Flush(true);
                }
                // Replace conserve les ACL propres au fichier existant. Move
                // est reserve aux creations et ne remplace jamais un intrus.
                if (overwrite && File.Exists(path)) File.Replace(temporary, path, null);
                else File.Move(temporary, path, false);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        private static void ValidateName(string name)
        {
            if (string.IsNullOrWhiteSpace(name) || Path.GetFileName(name) != name ||
                name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                !name.EndsWith(".maFile", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Invalid account filename.");
        }

        private static string NewTemporaryName() => ".sda-write-" + Guid.NewGuid().ToString("N") + ".tmp";

        private static void Clear(Snapshot snapshot)
        {
            if (snapshot.Manifest != null) CryptographicOperations.ZeroMemory(snapshot.Manifest);
            foreach (var file in snapshot.Files ?? new List<StoredFile>())
                if (file?.Content != null) CryptographicOperations.ZeroMemory(file.Content);
        }

        private sealed class Snapshot
        {
            public byte[] Manifest { get; set; }
            public string ManifestTemporaryName { get; set; }
            public List<StoredFile> Files { get; set; } = new List<StoredFile>();
        }

        private sealed class StoredFile
        {
            public string Name { get; set; }
            public string TemporaryName { get; set; }
            public byte[] Content { get; set; }
        }
    }
}
