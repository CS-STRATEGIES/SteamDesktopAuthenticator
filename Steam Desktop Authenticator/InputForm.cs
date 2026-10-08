using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Steam_Desktop_Authenticator
{
    public partial class InputForm : Form
    {
        public bool Canceled = false;
        private bool userClosed = true;
        private readonly bool allowEmpty;

        public InputForm(string label, bool password = false, bool allowEmpty = false)
        {
            InitializeComponent();
            this.labelText.Text = label;
            this.allowEmpty = allowEmpty;

            if (password)
            {
                this.txtBox.PasswordChar = '*';
            }
        }

        private void btnAccept_Click(object sender, EventArgs e)
        {
            this.Canceled = !allowEmpty && string.IsNullOrEmpty(this.txtBox.Text);
            this.userClosed = false;
            this.Close();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            this.Canceled = true;
            this.userClosed = false;
            this.Close();
        }

        private void InputForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (this.userClosed)
            {
                // Set Canceled = true when the user hits the X button.
                this.Canceled = true;
            }
        }
    }
}
