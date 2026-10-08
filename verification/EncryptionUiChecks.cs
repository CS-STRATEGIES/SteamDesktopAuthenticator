using System;
using System.Reflection;
using System.Windows.Forms;
using Steam_Desktop_Authenticator;

internal static class EncryptionUiChecks
{
    private static int checks;

    internal static int Run()
    {
        checks = 0;
        // Composants en memoire exclusivement : pas de Show/ShowDialog,
        // MainForm, timer, Manifest, compte ou appel reseau.
        using (var form = new InputForm("Offline encryption check"))
        {
            Click(form, "btnAccept_Click");
            Check(form.Canceled, "Une validation vide reste annulee sans autorisation explicite");
        }

        using (var form = new InputForm("Offline encryption check", password: true, allowEmpty: true))
        {
            Check(form.txtBox.PasswordChar == '*', "La nouvelle phrase de chiffrement est masquee");
            Click(form, "btnAccept_Click");
            Check(!form.Canceled, "Valider un champ vide autorise explicitement le retrait du chiffrement");
        }

        using (var form = new InputForm("Offline encryption check", password: true))
        {
            form.txtBox.Text = "mot-de-passe-fictif-interface";
            Click(form, "btnAccept_Click");
            Check(!form.Canceled, "Une phrase non vide reste acceptee avec les options par defaut");
        }

        foreach (var text in new[] { "", "mot-de-passe-fictif-interface" })
        {
            var label = text.Length == 0 ? "vide" : "non vide";
            using (var form = new InputForm("Offline encryption check", password: true, allowEmpty: true))
            {
                form.txtBox.Text = text;
                Click(form, "btnCancel_Click");
                Check(form.Canceled, "Cancel annule le changement meme avec un champ " + label);
            }

            using (var form = new InputForm("Offline encryption check", password: true, allowEmpty: true))
            {
                form.txtBox.Text = text;
                // Meme evenement que la croix de fermeture, sans creer de fenetre.
                typeof(Form).GetMethod("OnFormClosing", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .Invoke(form, new object[] { new FormClosingEventArgs(CloseReason.UserClosing, false) });
                Check(form.Canceled, "Fermer par la croix annule le changement avec un champ " + label);
            }
        }

        return checks;
    }

    private static void Click(InputForm form, string handler)
    {
        typeof(InputForm).GetMethod(handler, BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(form, new object[] { form, EventArgs.Empty });
    }

    private static void Check(bool condition, string label)
    {
        if (!condition) throw new InvalidOperationException(label);
        checks++;
        Console.WriteLine("OK: " + label);
    }
}
