using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using Newtonsoft.Json;
using SteamAuth;
using SteamKit2;
using Steam_Desktop_Authenticator;

internal static class OfflineChecks
{
    private static int checks;

    [STAThread]
    private static void Main()
    {
        // Donnees fictives exclusivement. Aucun appel reseau ni fichier de compte.
        var account = new SteamGuardAccount
        {
            SharedSecret = Convert.ToBase64String(Encoding.ASCII.GetBytes("12345678901234567890")),
            IdentitySecret = Convert.ToBase64String(new byte[20]),
            AccountName = "offline-fixture",
            Session = new SessionData { SteamID = 76561198000000000 }
        };
        Equal("PV9M4", account.GenerateSteamGuardCodeForTime(59), "Code Steam Guard, vecteur fixe");
        var serialized = JsonConvert.SerializeObject(account);
        var restored = JsonConvert.DeserializeObject<SteamGuardAccount>(serialized);
        Equal(account.SharedSecret, restored.SharedSecret, "Import du shared_secret");
        Equal(account.IdentitySecret, restored.IdentitySecret, "Import du identity_secret");
        Equal(account.Session.SteamID, restored.Session.SteamID, "Import de l'identite Steam");

        var saltBytes = Encoding.ASCII.GetBytes("12345678");
        var ivBytes = new byte[16];
        var salt = Convert.ToBase64String(saltBytes);
        var iv = Convert.ToBase64String(ivBytes);
        const string password = "mot-de-passe-fictif";
        // Reconstitue independamment le format historique de SDA.
        using var aes = Aes.Create();
        aes.Key = Rfc2898DeriveBytes.Pbkdf2(password, saltBytes, 50000, HashAlgorithmName.SHA1, 32);
        aes.IV = ivBytes;
        var plaintext = new UTF8Encoding(false).GetBytes(serialized);
        var legacyCiphertext = Convert.ToBase64String(aes.EncryptCbc(plaintext, ivBytes));
        Equal(serialized, FileEncryptor.DecryptData(password, salt, iv, legacyCiphertext), "Lecture du format chiffre historique");
        Equal(legacyCiphertext, FileEncryptor.EncryptData(password, salt, iv, serialized), "Ecriture compatible du format chiffre");
        Equal(null, FileEncryptor.DecryptData("mauvais-mot-de-passe", salt, iv, legacyCiphertext), "Rejet du mauvais mot de passe");

        var defaults = new Manifest();
        Equal(false, defaults.AutoConfirmTrades, "Confirmations d'echanges desactivees par defaut");
        Equal(false, defaults.AutoConfirmMarketTransactions, "Confirmations du marche desactivees par defaut");

        // Construit les composants WinForms sans afficher de fenetre ni connecter Steam.
        using var login = new LoginForm(LoginForm.LoginType.Initial);
        using var phone = new PhoneInputForm(null);
        using var popup = new TradePopupForm();
        using var button = new ConfirmationButton();
        Equal(DesignerSerializationVisibility.Hidden,
            ((DesignerSerializationVisibilityAttribute)TypeDescriptor.GetProperties(popup)["Account"].Attributes[typeof(DesignerSerializationVisibilityAttribute)]).Visibility,
            "Secrets exclus de la serialisation du designer");
        var steam = new SteamClient();
        Equal(false, steam.IsConnected, "Initialisation SteamKit sans connexion");
        checks += TransferChecks.Run();
        Console.WriteLine($"{checks} verifications hors ligne reussies.");
    }

    private static void Equal<T>(T expected, T actual, string label)
    {
        if (!object.Equals(expected, actual))
            throw new InvalidOperationException(label);
        checks++;
        Console.WriteLine("OK: " + label);
    }
}
