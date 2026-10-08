using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using ProtoBuf;
using SteamAuth;
using SteamKit2;
using SteamKit2.Internal;
using Steam_Desktop_Authenticator;

internal static class TransferChecks
{
    private const ulong SteamId = 76561198000000000;
    private static int checks;
    private static readonly SessionData Session = new SessionData
    {
        SteamID = SteamId, AccessToken = "offline-access-token", RefreshToken = "offline-refresh-token"
    };

    internal static int Run()
    {
        // Le handler intercepte TOUS les appels. Aucune requete Steam ni compte reel.
        ProtocolChecks().GetAwaiter().GetResult();
        StorageChecks();
        using var transfer = new TransferAuthenticatorForm();
        using var login = new LoginForm(LoginForm.LoginType.Transfer);
        Check(transfer.Controls.Count > 0, "Construction du parcours graphique de transfert");
        return checks;
    }

    private static async Task ProtocolChecks()
    {
        using var handler = new FakeSteam();
        handler.Replies.Enqueue(() => Response(Array.Empty<byte>()));
        handler.Replies.Enqueue(() => Response(Serialize(TokenResponse())));
        using var http = new HttpClient(handler);
        var service = new AuthenticatorTransfer(http, Session);
        bool saved = false;
        await Throws<InvalidOperationException>(() => service.FinishAsync("12345", _ => { }), "Impossible de finaliser sans challenge");
        await service.StartAsync();
        await Throws<ArgumentException>(() => service.FinishAsync(" ", _ => { }), "SMS vide refuse avant appel reseau");
        var account = await service.FinishAsync("12345", reply => { saved = reply.Body.Length > 0; });
        Check(saved && account.FullyEnrolled && account.Session.SteamID == SteamId, "Sauvegarde avant retour du compte transfere");
        Check(account.SharedSecret == Convert.ToBase64String(Encoding.ASCII.GetBytes("12345678901234567890")), "Secret de connexion importe");
        Check(account.IdentitySecret == Convert.ToBase64String(Enumerable.Repeat((byte)42, 20).ToArray()), "Secret de confirmation importe");
        Check(handler.Paths.SequenceEqual(new[] {
            "/ITwoFactorService/RemoveAuthenticatorViaChallengeStart/v1/",
            "/ITwoFactorService/RemoveAuthenticatorViaChallengeContinue/v1/"
        }), "Parcours sans suppression ni ajout d'authentificateur");
        var request = Deserialize<CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Request>(handler.Payloads[1]);
        Check(request.generate_new_token && request.version == 2 && request.sms_code == "12345", "Remplacement demande explicitement, version 2");
        Check(Convert.ToHexString(handler.Payloads[1]) == "0A05313233343510011802", "Octets de requete conformes au schema Steam");
        await Throws<InvalidOperationException>(() => service.FinishAsync("12345", _ => { }), "Pas de double transfert apres succes");
        Check(handler.Paths.Count == 2, "Aucun appel supplementaire apres succes");

        using var invalid = new FakeSteam();
        invalid.Replies.Enqueue(() => Response(Array.Empty<byte>()));
        invalid.Replies.Enqueue(() => Response(Array.Empty<byte>(), EResult.SMSCodeFailed));
        invalid.Replies.Enqueue(() => Response(Serialize(TokenResponse())));
        using var invalidHttp = new HttpClient(invalid);
        var retry = new AuthenticatorTransfer(invalidHttp, Session);
        await retry.StartAsync();
        await Throws<InvalidSmsCodeException>(() => retry.FinishAsync("00000", _ => { }), "Refus SMS explicite reconnu");
        await retry.FinishAsync("12345", _ => { });
        Check(invalid.Paths.Count == 3, "Nouvelle saisie permise seulement apres refus SMS");

        using var lost = new FakeSteam();
        lost.Replies.Enqueue(() => Response(Array.Empty<byte>()));
        lost.Replies.Enqueue(() => throw new HttpRequestException("offline network failure"));
        using var lostHttp = new HttpClient(lost);
        var uncertain = new AuthenticatorTransfer(lostHttp, Session);
        await uncertain.StartAsync();
        await Throws<HttpRequestException>(() => uncertain.FinishAsync("12345", _ => { }), "Perte reseau apres soumission");
        await Throws<InvalidOperationException>(() => uncertain.FinishAsync("12345", _ => { }), "Pas de renvoi apres resultat incertain");
        Check(lost.Paths.Count == 2, "Aucun repli vers suppression apres coupure reseau");

        foreach (var header in new[] { "missing", "bad", "duplicate", "http-error" })
        {
            using var failedReply = new FakeSteam();
            failedReply.Replies.Enqueue(() => Response(Array.Empty<byte>()));
            failedReply.Replies.Enqueue(() =>
            {
                var response = Response(Serialize(TokenResponse()));
                if (header == "http-error") response.StatusCode = HttpStatusCode.ServiceUnavailable;
                else
                {
                    response.Headers.Remove("x-eresult");
                    if (header == "bad") response.Headers.Add("x-eresult", "invalid");
                    if (header == "duplicate") response.Headers.Add("x-eresult", new[] { "1", "1" });
                }
                return response;
            });
            using var failedHttp = new HttpClient(failedReply);
            var failed = new AuthenticatorTransfer(failedHttp, Session);
            await failed.StartAsync();
            saved = false;
            await Throws<InvalidOperationException>(() => failed.FinishAsync("12345", _ => saved = true), "Statut HTTP ou resultat Steam invalide refuse");
            Check(saved, "Corps preserve meme avec des en-tetes invalides");
        }

        using var refused = new FakeSteam();
        refused.Replies.Enqueue(() => Response(Array.Empty<byte>(), EResult.Fail));
        using var refusedHttp = new HttpClient(refused);
        var noStart = new AuthenticatorTransfer(refusedHttp, Session);
        await Throws<InvalidOperationException>(() => noStart.StartAsync(), "Refus de demarrage pris en compte");
        await Throws<InvalidOperationException>(() => noStart.FinishAsync("12345", _ => { }), "Refus de demarrage empeche la finalisation");

        using var disk = new FakeSteam();
        disk.Replies.Enqueue(() => Response(Array.Empty<byte>()));
        disk.Replies.Enqueue(() => Response(Serialize(TokenResponse())));
        using var diskHttp = new HttpClient(disk);
        var diskFailure = new AuthenticatorTransfer(diskHttp, Session);
        await diskFailure.StartAsync();
        await Throws<IOException>(() => diskFailure.FinishAsync("12345", _ => throw new IOException()), "Echec de sauvegarde ne produit aucun faux succes");
        await Throws<InvalidOperationException>(() => diskFailure.FinishAsync("12345", _ => { }), "Echec disque ne relance pas le transfert");

        // Des reponses mal formees doivent quand meme etre sauvegardees pour recuperation.
        foreach (var body in new[] { Array.Empty<byte>(), new byte[] { 255 }, Serialize(TokenResponse(SteamId + 1)),
            Serialize(new CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response { success = true }),
            Serialize(TokenResponse(success: false)), Serialize(TokenResponse(missingIdentity: true)) })
        {
            using var malformed = new FakeSteam();
            malformed.Replies.Enqueue(() => Response(Array.Empty<byte>()));
            malformed.Replies.Enqueue(() => Response(body));
            using var malformedHttp = new HttpClient(malformed);
            var bad = new AuthenticatorTransfer(malformedHttp, Session);
            await bad.StartAsync();
            saved = false;
            await Throws<InvalidOperationException>(() => bad.FinishAsync("12345", _ => saved = true), "Reponse incomplete ou mauvais compte refuse");
            Check(saved, "Reponse refusee conservee avant validation");
        }
    }

    private static void StorageChecks()
    {
        var root = Path.Combine(Path.GetTempPath(), "sda-offline-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            const string passphrase = "mot-de-passe-de-test-uniquement";
            var backup = new TransferBackup(root, Session, passphrase);
            backup.Prepare();
            Check(TransferBackup.Open(backup.FilePath, passphrase).Reply == null, "Sauvegarde prealable lisible sans resultat invente");
            var reply = new TransferReply { HttpStatus = 200, Result = 1, Body = Serialize(TokenResponse()) };
            backup.SaveReply(reply);
            var restored = TransferBackup.Open(backup.FilePath, passphrase);
            var account = AuthenticatorTransfer.ReadAccount(restored.Reply, restored.Session);
            Check(account.RevocationCode == "R00000" && restored.Session.RefreshToken == Session.RefreshToken, "Recuperation complete des secrets et de la session");
            var text = File.ReadAllText(backup.FilePath);
            Check(!text.Contains(Session.AccessToken) && !text.Contains(account.SharedSecret) && !text.Contains(account.RevocationCode), "Aucun secret en clair dans la sauvegarde");
            ThrowsSync<CryptographicException>(() => TransferBackup.Open(backup.FilePath, "incorrect"), "Mauvais mot de passe refuse");
            var tampered = JObject.Parse(text);
            var bytes = Convert.FromBase64String((string)tampered["Ciphertext"]);
            bytes[0] ^= 1;
            tampered["Ciphertext"] = Convert.ToBase64String(bytes);
            var corruptPath = Path.Combine(root, "corrupt.sda-transfer");
            File.WriteAllText(corruptPath, tampered.ToString());
            ThrowsSync<CryptographicException>(() => TransferBackup.Open(corruptPath, passphrase), "Sauvegarde alteree refusee par AES-GCM");

            var manifest = new Manifest { Entries = new List<Manifest.ManifestEntry>() };
            // Simuler un manifest impossible a remplacer, puis recuperer depuis la sauvegarde.
            var manifestPath = Path.Combine(root, "manifest.json");
            Directory.CreateDirectory(manifestPath);
            ThrowsSync<UnauthorizedAccessException>(() => TransferBackup.SaveAccount(root, manifest, account, passphrase), "Echec d'ecriture du manifest detecte");
            Check(manifest.Entries.Count == 0, "Manifest en memoire conserve apres echec");
            Directory.Delete(manifestPath);
            TransferBackup.SaveAccount(root, manifest, account, passphrase);
            var entry = manifest.Entries.Single();
            var encrypted = File.ReadAllText(Path.Combine(root, entry.Filename));
            var decrypted = FileEncryptor.DecryptData(passphrase, entry.Salt, entry.IV, encrypted);
            var maFile = JsonConvert.DeserializeObject<SteamGuardAccount>(decrypted);
            Check(manifest.Encrypted && maFile.SharedSecret == account.SharedSecret, "maFile chiffre compatible SDA apres recuperation");
            var previous = File.ReadAllText(manifestPath);
            ThrowsSync<InvalidOperationException>(() => TransferBackup.SaveAccount(root, manifest, account, passphrase), "Compte existant jamais ecrase");
            Check(previous == File.ReadAllText(manifestPath), "Manifest inchange apres refus de doublon");
            Check(Directory.GetFiles(root, "*.tmp").Length == 0, "Aucun fichier temporaire laisse apres sauvegarde");
            backup.MarkSubmitting();
            Check(TransferBackup.Open(backup.FilePath, passphrase).Reply == null, "Ancien resultat efface avant une nouvelle soumission autorisee");
        }
        finally
        {
            // Uniquement le repertoire aleatoire cree par ce test, jamais un maFiles utilisateur.
            Directory.Delete(root, true);
        }
    }

    private static CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response TokenResponse(ulong steamId = SteamId, bool success = true, bool missingIdentity = false)
    {
        return new CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response
        {
            success = success,
            replacement_token = new CRemoveAuthenticatorViaChallengeContinue_Replacement_Token
            {
                shared_secret = Encoding.ASCII.GetBytes("12345678901234567890"),
                identity_secret = missingIdentity ? null : Enumerable.Repeat((byte)42, 20).ToArray(),
                steamid = steamId, revocation_code = "R00000", account_name = "offline-fixture",
                serial_number = 42, status = 1, server_time = 59
            }
        };
    }

    private static byte[] Serialize<T>(T value)
    {
        using var buffer = new MemoryStream();
        Serializer.Serialize(buffer, value);
        return buffer.ToArray();
    }

    private static T Deserialize<T>(byte[] value)
    {
        using var buffer = new MemoryStream(value);
        return Serializer.Deserialize<T>(buffer);
    }

    private static HttpResponseMessage Response(byte[] bytes, EResult result = EResult.OK)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
        response.Headers.Add("x-eresult", ((int)result).ToString());
        return response;
    }

    private sealed class FakeSteam : HttpMessageHandler
    {
        internal readonly Queue<Func<HttpResponseMessage>> Replies = new();
        internal readonly List<string> Paths = new();
        internal readonly List<byte[]> Payloads = new();
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Check(request.RequestUri.Scheme == "https" && request.RequestUri.Host == "api.steampowered.com" && request.Method == HttpMethod.Post,
                "Appel POST uniquement vers Steam en HTTPS");
            Paths.Add(request.RequestUri.AbsolutePath);
            var content = (MultipartFormDataContent)request.Content;
            var part = content.Single();
            Check(part.Headers.ContentDisposition.Name.Trim('"') == "input_protobuf_encoded", "Corps protobuf attendu par Steam");
            Payloads.Add(Convert.FromBase64String(await part.ReadAsStringAsync(cancellationToken)));
            return Replies.Dequeue()();
        }
    }

    private static void Check(bool condition, string label = "Secret de connexion importe")
    {
        if (!condition) throw new InvalidOperationException(label);
        checks++;
        Console.WriteLine("OK: " + label);
    }

    private static async Task Throws<T>(Func<Task> action, string label) where T : Exception
    {
        try { await action(); }
        catch (T) { Check(true, label); return; }
        throw new InvalidOperationException(label);
    }

    private static void ThrowsSync<T>(Action action, string label) where T : Exception
    {
        try { action(); }
        catch (T) { Check(true, label); return; }
        throw new InvalidOperationException(label);
    }
}
