using SteamAuth;
using SteamKit2.Authentication;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Steam_Desktop_Authenticator
{
    internal class UserFormAuthenticator : IAuthenticator
    {
        private SteamGuardAccount account;
        private int deviceCodesGenerated = 0;
        private readonly bool allowPhoneCode;

        public UserFormAuthenticator(SteamGuardAccount account, bool allowPhoneCode = false)
        {
            this.account = account;
            this.allowPhoneCode = allowPhoneCode;
        }

        public Task<bool> AcceptDeviceConfirmationAsync()
        {
            return Task.FromResult(false);
        }

        public async Task<string> GetDeviceCodeAsync(bool previousCodeWasIncorrect)
        {
            // If a code fails wait 30 seconds for a new one to regenerate
            if (previousCodeWasIncorrect)
            {
                // After 2 tries tell the user that there seems to be an issue
                if (deviceCodesGenerated > 2)
                    MessageBox.Show("There seems to be an issue logging into your account with these two factor codes. Are you sure SDA is still your authenticator?");

                await Task.Delay(30000);
            }

            string deviceCode;

            if (account == null)
            {
                if (!allowPhoneCode)
                {
                    MessageBox.Show("This account already has an authenticator. Keep it enabled and use File > Transfer Authenticator instead.", "Steam Login", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    throw new System.OperationCanceledException();
                }
                using var input = new InputForm(previousCodeWasIncorrect ?
                    "That code was rejected. Enter a fresh Steam Guard code from your current phone." :
                    "Enter the current Steam Guard code shown by the Steam app on your phone.", true);
                input.ShowDialog();
                if (input.Canceled) throw new System.OperationCanceledException();
                deviceCode = input.txtBox.Text.Trim().ToUpperInvariant();
            }
            else
            {
                deviceCode = await account.GenerateSteamGuardCodeAsync();
                deviceCodesGenerated++;
            }

            return deviceCode;
        }

        public Task<string> GetEmailCodeAsync(string email, bool previousCodeWasIncorrect)
        {
            string message = "Enter the code sent to your email:";
            if (previousCodeWasIncorrect)
            {
                message = "The code you provided was invalid. Enter the code sent to your email:";
            }

            InputForm emailForm = new InputForm(message);
            emailForm.ShowDialog();
            if (emailForm.Canceled) throw new System.OperationCanceledException();
            return Task.FromResult(emailForm.txtBox.Text);
        }
    }
}
