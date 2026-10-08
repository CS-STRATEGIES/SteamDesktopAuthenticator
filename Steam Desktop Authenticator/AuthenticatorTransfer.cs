using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using ProtoBuf;
using SteamAuth;
using SteamKit2;
using SteamKit2.Internal;

namespace Steam_Desktop_Authenticator
{
    // Protocole ITwoFactorService. Aucun appel a RemoveAuthenticator/AddAuthenticator.
    internal sealed class AuthenticatorTransfer
    {
        private readonly HttpClient http;
        private readonly SessionData session;
        private bool started;
        private bool startRequested;
        private bool submitted;

        internal AuthenticatorTransfer(HttpClient http, SessionData session)
        {
            this.http = http;
            this.session = session;
            if (session == null || session.SteamID == 0 || string.IsNullOrWhiteSpace(session.AccessToken))
                throw new InvalidOperationException("A mobile Steam session is required.");
        }

        internal async Task StartAsync()
        {
            if (startRequested) throw new InvalidOperationException("The SMS challenge was already requested.");
            startRequested = true;
            var reply = await SendAsync("RemoveAuthenticatorViaChallengeStart",
                new CTwoFactor_RemoveAuthenticatorViaChallengeStart_Request());
            RequireSuccess(reply);
            started = true;
            // Steam peut omettre success dans Start. x-eresult fait autorite.
        }

        internal async Task<SteamGuardAccount> FinishAsync(string smsCode, Action<TransferReply> saveReply)
        {
            if (!started || submitted) throw new InvalidOperationException("This transfer cannot be submitted again.");
            smsCode = smsCode?.Trim();
            if (string.IsNullOrEmpty(smsCode) || smsCode.Length > 32 || !smsCode.All(char.IsAsciiLetterOrDigit))
                throw new ArgumentException("Enter the SMS code received from Steam.");
            ArgumentNullException.ThrowIfNull(saveReply);

            // Une perte reseau apres envoi peut survenir APRES le remplacement chez Steam.
            // Pas de nouvelle tentative automatique, ni de repli vers une suppression.
            submitted = true;
            var reply = await SendAsync("RemoveAuthenticatorViaChallengeContinue",
                new CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Request
                {
                    sms_code = smsCode,
                    generate_new_token = true,
                    version = 2
                });
            // Conserver la reponse chiffree AVANT toute interpretation ou ecriture du maFile.
            saveReply(reply);
            if (reply.HttpStatus == 200 && reply.Result == (int)EResult.SMSCodeFailed)
            {
                submitted = false;
                throw new InvalidSmsCodeException();
            }
            return ReadAccount(reply, session);
        }

        internal static SteamGuardAccount ReadAccount(TransferReply reply, SessionData session)
        {
            RequireSuccess(reply);
            CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response response;
            try
            {
                using var stream = new MemoryStream(reply.Body);
                response = Serializer.Deserialize<CTwoFactor_RemoveAuthenticatorViaChallengeContinue_Response>(stream);
            }
            catch (Exception)
            {
                throw new InvalidOperationException("Steam returned an unreadable transfer response. Keep the encrypted recovery backup.");
            }
            var token = response.replacement_token;
            if ((response.ShouldSerializesuccess() && !response.success) || token == null ||
                token.shared_secret == null || token.shared_secret.Length == 0 ||
                token.identity_secret == null || token.identity_secret.Length == 0 ||
                string.IsNullOrWhiteSpace(token.revocation_code) || string.IsNullOrWhiteSpace(token.account_name) ||
                (token.ShouldSerializestatus() && token.status != 1) ||
                (token.steamid != 0 && token.steamid != session.SteamID))
                throw new InvalidOperationException("Steam did not return a complete replacement authenticator for this account. Keep the encrypted recovery backup.");

            return new SteamGuardAccount
            {
                SharedSecret = Convert.ToBase64String(token.shared_secret),
                IdentitySecret = Convert.ToBase64String(token.identity_secret),
                Secret1 = Convert.ToBase64String(token.secret_1 ?? Array.Empty<byte>()),
                SerialNumber = token.serial_number.ToString(CultureInfo.InvariantCulture),
                RevocationCode = token.revocation_code,
                URI = token.uri,
                ServerTime = checked((long)token.server_time),
                AccountName = token.account_name,
                TokenGID = token.token_gid,
                Status = 1,
                DeviceID = "android:" + Guid.NewGuid(),
                FullyEnrolled = true,
                Session = session
            };
        }

        private async Task<TransferReply> SendAsync<T>(string method, T payload)
        {
            using var buffer = new MemoryStream();
            Serializer.Serialize(buffer, payload);
            // Meme transport que les clients mobiles. Ne jamais journaliser l'URL,
            // les en-tetes, le corps ou les exceptions HttpClient (jeton dans l'URL).
            var url = "https://api.steampowered.com/ITwoFactorService/" + method +
                "/v1/?access_token=" + Uri.EscapeDataString(session.AccessToken);
            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            var form = new MultipartFormDataContent();
            form.Add(new StringContent(Convert.ToBase64String(buffer.ToArray())), "input_protobuf_encoded");
            request.Content = form;
            using var response = await http.SendAsync(request);
            var bytes = await response.Content.ReadAsByteArrayAsync();
            int result = 0;
            if (response.Headers.TryGetValues("x-eresult", out var values))
            {
                var headers = values.ToArray();
                if (headers.Length == 1)
                    int.TryParse(headers[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out result);
            }
            return new TransferReply { HttpStatus = (int)response.StatusCode, Result = result, Body = bytes };
        }

        private static void RequireSuccess(TransferReply reply)
        {
            if (reply.HttpStatus != 200 || reply.Result != (int)EResult.OK)
                throw new InvalidOperationException($"Steam refused the request (HTTP {reply.HttpStatus}, result {reply.Result}). Check your verified phone number and session. Do not remove your authenticator.");
        }
    }

    internal sealed class TransferReply
    {
        public int HttpStatus { get; set; }
        public int Result { get; set; }
        public byte[] Body { get; set; }
    }

    internal sealed class InvalidSmsCodeException : Exception
    {
        internal InvalidSmsCodeException() : base("Steam rejected the SMS code. Check the code and try again.") { }
    }
}
