using System;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Windows.Forms;
using SteamAuth;

namespace Steam_Desktop_Authenticator
{
    public sealed class TransferAuthenticatorForm : Form
    {
        private readonly Button transfer = new Button { Text = "Sign in and transfer", AutoSize = true };
        private readonly Button recover = new Button { Text = "Recover saved transfer", AutoSize = true };
        private readonly Label status = new Label { AutoSize = true, MaximumSize = new Size(510, 0) };
        private bool busy;
        private bool terminal;
        private readonly bool recoveryOnly;

        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
        public string EncryptionPassphrase { get; private set; }

        public TransferAuthenticatorForm(bool recoveryOnly = false)
        {
            this.recoveryOnly = recoveryOnly;
            terminal = recoveryOnly;
            transfer.Enabled = !recoveryOnly;
            Text = recoveryOnly ? "Recover saved transfer" : "Transfer Authenticator";
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ClientSize = new Size(560, 315);
            Font = new Font("Segoe UI", 9);
            var panel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown,
                WrapContents = false, Padding = new Padding(18), AutoScroll = true
            };
            panel.Controls.Add(new Label
            {
                AutoSize = true, MaximumSize = new Size(510, 0),
                Text = recoveryOnly
                    ? "SDA could not unlock its accounts or read its account index. Do not remove your Steam authenticator or start another transfer.\n\n" +
                      "Recover an encrypted .sda-transfer backup below, or close SDA and restore your complete maFiles backup. Recovery is offline.\n\n" +
                      "Existing account files and the previous index are preserved. An indexed account that cannot be read requires your confirmation before local restoration."
                    : "Keep Steam Guard enabled on your phone. You need its current login code and access to the verified phone number for the SMS.\n\n" +
                    "Submitting the SMS code replaces the phone authenticator with SDA. Steam documents a 2-day trade and market restriction for transfers; Steam determines the actual restriction.\n\n" +
                    "Save the encryption password and the new recovery code. Do not remove the existing authenticator first."
            });
            panel.Controls.Add(transfer);
            panel.Controls.Add(recover);
            panel.Controls.Add(status);
            Controls.Add(panel);
            transfer.Click += Transfer_Click;
            recover.Click += Recover_Click;
            FormClosing += (_, e) =>
            {
                if (busy)
                {
                    e.Cancel = true;
                    MessageBox.Show(this, "Finish or cancel the current step before closing this window.", Text);
                }
            };
        }

        private void SetBusy(bool value)
        {
            busy = value;
            transfer.Enabled = !value && !terminal;
            recover.Enabled = !value;
        }

        private string RequestPassphrase(Manifest manifest, SteamGuardAccount recoveringAccount = null)
        {
            bool recovering = recoveringAccount != null;
            if (!manifest.Encrypted && manifest.Entries.Any(e => !recovering || e.SteamID != recoveringAccount.Session.SteamID))
                throw new InvalidOperationException("Use Setup Encryption on your existing accounts before transferring another account.");
            var prompt = manifest.Encrypted ? "Enter your current SDA encryption password." :
                "Choose an encryption password for SDA and its recovery backup. Save it securely.";
            if (recovering && !manifest.Entries.Any(e => e.SteamID != recoveringAccount.Session.SteamID))
                prompt = "Enter your current SDA encryption password. If it cannot be recovered, choose a new password for this restored account. Save it securely.";
            using var input = new InputForm(prompt, true);
            input.ShowDialog(this);
            if (input.Canceled || string.IsNullOrWhiteSpace(input.txtBox.Text)) return null;
            var password = input.txtBox.Text;
            if (manifest.Encrypted && !recovering)
            {
                if (!manifest.VerifyPasskey(password)) throw new InvalidOperationException("Incorrect SDA encryption password.");
            }
            else
            {
                using var confirmation = new InputForm("Enter the encryption password again.", true);
                confirmation.ShowDialog(this);
                if (confirmation.Canceled) return null;
                if (confirmation.txtBox.Text != password) throw new InvalidOperationException("The encryption passwords do not match.");
            }
            return password;
        }

        private async void Transfer_Click(object sender, EventArgs e)
        {
            if (recoveryOnly) return;
            SetBusy(true);
            TransferBackup backup = null;
            bool finalRequestAttempted = false;
            try
            {
                if (AccountStorageTransaction.IsPending(Path.Combine(Manifest.GetExecutableDir(), "maFiles")))
                    throw new InvalidOperationException("Restart SDA to recover the interrupted account update before starting a transfer.");
                using var login = new LoginForm(LoginForm.LoginType.Transfer);
                login.ShowDialog(this);
                if (login.Session == null) return;
                var manifest = Manifest.GetManifest();
                if (manifest.Entries.Any(e => e.SteamID == login.Session.SteamID))
                    throw new InvalidOperationException("This account already exists in SDA. No transfer was started.");
                var passphrase = RequestPassphrase(manifest);
                if (passphrase == null) return;
                var directory = Path.Combine(Manifest.GetExecutableDir(), "maFiles");
                backup = new TransferBackup(directory, login.Session, passphrase);
                backup.Prepare();

                // Interdire les redirections pour ne pas transmettre la session ailleurs.
                using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(45) };
                http.MaxResponseContentBufferSize = 1024 * 1024;
                var service = new AuthenticatorTransfer(http, login.Session);
                status.Text = "Requesting the SMS challenge...";
                await service.StartAsync();

                while (true)
                {
                    using var sms = new InputForm("Enter the SMS code from Steam. Submitting it transfers Steam Guard to SDA and invalidates the phone authenticator.", true);
                    sms.ShowDialog(this);
                    if (sms.Canceled) { status.Text = "Transfer cancelled before submitting the SMS code."; return; }
                    var code = sms.txtBox.Text.Trim();
                    if (code.Length == 0 || code.Length > 32 || !code.All(char.IsAsciiLetterOrDigit))
                    {
                        MessageBox.Show(this, "Enter only the SMS code received from Steam.", Text);
                        continue;
                    }
                    status.Text = "Transferring and saving the new authenticator...";
                    backup.MarkSubmitting();
                    finalRequestAttempted = true;
                    terminal = true;
                    SteamGuardAccount account;
                    try
                    {
                        account = await service.FinishAsync(code, reply => SaveReplyUntilStored(backup, reply));
                    }
                    catch (InvalidSmsCodeException ex)
                    {
                        finalRequestAttempted = false;
                        terminal = false;
                        MessageBox.Show(this, ex.Message, Text);
                        continue;
                    }
                    TransferBackup.SaveAccount(directory, manifest, account, passphrase);
                    EncryptionPassphrase = passphrase;
                    transfer.Enabled = false;
                    ShowSuccess(account, backup.FilePath);
                    return;
                }
            }
            catch (Exception ex)
            {
                // Les erreurs reseau et de fichiers ne doivent pas exposer de jetons ou de reponses.
                var message = ex is InvalidOperationException ? ex.Message : "The transfer could not be completed locally.";
                if (finalRequestAttempted)
                    message += "\nSteam may already have replaced the authenticator. Do not submit another transfer automatically. Use Recover saved transfer if a response was saved; otherwise check the account in Steam or contact Steam Support.";
                if (backup != null) message += "\nEncrypted recovery backup: " + backup.FilePath;
                MessageBox.Show(this, message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                status.Text = "Transfer stopped. Read the recovery instructions before trying again.";
            }
            finally
            {
                SetBusy(false);
                if (finalRequestAttempted) transfer.Enabled = false;
            }
        }

        private void SaveReplyUntilStored(TransferBackup backup, TransferReply reply)
        {
            while (true)
            {
                try { backup.SaveReply(reply); return; }
                catch (Exception)
                {
                    MessageBox.Show(this, "Steam replied but the encrypted backup could not be saved. Keep this window open and select another writable location. Do not repeat the transfer.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    using var target = new SaveFileDialog
                    {
                        Filter = "Encrypted transfer backup|*.sda-transfer",
                        FileName = "transfer-" + Guid.NewGuid().ToString("N") + ".sda-transfer",
                        OverwritePrompt = true
                    };
                    if (target.ShowDialog(this) == DialogResult.OK) backup.FilePath = target.FileName;
                }
            }
        }

        private void Recover_Click(object sender, EventArgs e)
        {
            SetBusy(true);
            try
            {
                using var file = new OpenFileDialog { Filter = "Encrypted transfer backup|*.sda-transfer" };
                if (file.ShowDialog(this) != DialogResult.OK) return;
                using var password = new InputForm("Enter the encryption password used for this transfer backup.", true);
                password.ShowDialog(this);
                if (password.Canceled) return;
                var backup = TransferBackup.Open(file.FileName, password.txtBox.Text);
                if (backup.Reply == null)
                    throw new InvalidOperationException("This backup contains no Steam response. It cannot restore new secrets. If the SMS was submitted, check the account with Steam before retrying.");
                var account = AuthenticatorTransfer.ReadAccount(backup.Reply, backup.Session);
                var directory = Path.Combine(Manifest.GetExecutableDir(), "maFiles");
                var manifest = recoveryOnly ? Manifest.LoadForRecovery(directory) : Manifest.GetManifest();
                var passphrase = RequestPassphrase(manifest, account);
                if (passphrase == null) return;
                if (TransferBackup.ValidateRecovery(directory, manifest, account, passphrase) &&
                    MessageBox.Show(this,
                        "This account cannot be read with the password you entered. This may mean a wrong password or damaged data. Try your current SDA password first if it has changed.\n\n" +
                        "Restore this local account from the selected backup? Use the backup from your latest successful transfer. SDA will preserve the original account file and a copy of the complete index. No request will be sent to Steam.",
                        Text, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                    return;
                TransferBackup.RecoverAccount(directory, manifest, account, passphrase);
                EncryptionPassphrase = passphrase;
                ShowSuccess(account, backup.FilePath);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex is InvalidOperationException ? ex.Message : "Recovery failed. Check the backup, password and writable disk space. Keep the backup.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally { SetBusy(false); }
            if (recoveryOnly && EncryptionPassphrase != null) Close();
        }

        private void ShowSuccess(SteamGuardAccount account, string backupPath)
        {
            status.Text = "Authenticator saved. Keep the recovery backup and encryption password.";
            MessageBox.Show(this, "Authenticator saved in SDA. Save your NEW recovery code securely:\n\n" +
                account.RevocationCode + "\n\nEncrypted recovery backup:\n" + backupPath +
                "\n\nKeep Steam Guard enabled. Check Steam for the actual trade and market restriction.", Text,
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
