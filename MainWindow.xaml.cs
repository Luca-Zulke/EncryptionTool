using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using WPFCustomMessageBox;

namespace EncryptionTool
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btnAES_Click(object sender, RoutedEventArgs e)
        {
            string name = txtNameKey.Text;
            if (name.Length < 3)
            {
                MessageBox.Show("Input moet groter zijn dan 3 karakters", "Error", MessageBoxButton.OK);
            }
            else
            {
                Aes aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.FeedbackSize = 128;
                aes.Padding = PaddingMode.Zeros;
                aes.GenerateKey();
                aes.GenerateIV();

                string key = Convert.ToBase64String(aes.Key);
                string iv = Convert.ToBase64String(aes.IV);
                File.WriteAllText(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"{name}-KEY.txt"), key);
                File.WriteAllText(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"{name}-IV.txt"), iv);
                MessageBox.Show("2 Files zijn aangemaakt op de Desktop", "", MessageBoxButton.OK);
                txtNameKey.Clear();
            }
        }

        private void btnRSA_Click(object sender, RoutedEventArgs e)
        {
            string name = txtNameKey.Text;
            if (name.Length < 3)
            {
                MessageBox.Show("Input moet groter zijn dan 3 karakters", "Error", MessageBoxButton.OK);
            }
            else
            {
                RSA rsa = RSA.Create();

                File.WriteAllText(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"{name}-RSA_KEY_PRIVATE.xml"), rsa.ToXmlString(true));
                File.WriteAllText(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"{name}-RSA_KEY_PUBLIC.xml"), rsa.ToXmlString(false));
                MessageBox.Show("2 Files zijn aangemaakt op de Desktop", "", MessageBoxButton.OK);
                txtNameKey.Clear();
            }
        }

        private void btnEncryptText_Click(object sender, RoutedEventArgs e)
        {
            if (!(txtToEncrypt.Text.Length < 1))
            {
                OpenFileDialog ofd = new OpenFileDialog();

                GetKeyAndIV(ofd);

                byte[] encrypted = EncryptStringToBytes_Aes(txtToEncrypt.Text, KeyBytes, IVBytes);

                txtEncrypted.Text = Convert.ToBase64String(encrypted);
            }
            else
            {
                MessageBox.Show("Input moet karakters bevatten", "Error", MessageBoxButton.OK);
            }
           
        }

        private void btnEncryptTextFile_Click(object sender, RoutedEventArgs e)
        {
            txtToEncrypt.Clear();

            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Title = "Selecteer het bestand dat u wilt encrypteren";
            ofd.DefaultExt = ".txt";
            ofd.Filter = "Text|*.txt|All|*.*";
            ofd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            if (ofd.ShowDialog() == true)
            {
                try
                {
                    Stream myStream;
                    if ((myStream = ofd.OpenFile()) != null)
                    {
                        using (StreamReader sr = new StreamReader(myStream))
                        {
                            Input = sr.ReadToEnd();
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: Could not read file from disk. Original error: " + ex.Message);
                }
            }

            GetKeyAndIV(ofd);

            byte[] encrypted = EncryptStringToBytes_Aes(Input, KeyBytes, IVBytes);

            txtEncrypted.Text = Convert.ToBase64String(encrypted);

        }

        private void GetKeyAndIV(OpenFileDialog ofd)
        {
            ofd.Title = "Selecteer de KEY";
            ofd.DefaultExt = ".txt";
            ofd.Filter = "Text|*.txt|All|*.*";
            ofd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            if (ofd.ShowDialog() == true)
            {
                try
                {
                    Stream myStream;
                    if ((myStream = ofd.OpenFile()) != null)
                    {
                        using (StreamReader sr = new StreamReader(myStream))
                        {
                            Key = sr.ReadToEnd();
                            KeyBytes = Convert.FromBase64String(Key);
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: Could not read file from disk. Original error: " + ex.Message);
                }
            }

            ofd.Title = "Selecteer de IV";
            ofd.DefaultExt = ".txt";
            ofd.Filter = "Text|*.txt|All|*.*";
            ofd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            if (ofd.ShowDialog() == true)
            {
                try
                {
                    Stream myStream;
                    if ((myStream = ofd.OpenFile()) != null)
                    {
                        using (StreamReader sr = new StreamReader(myStream))
                        {
                            IV = sr.ReadToEnd();
                            IVBytes = Convert.FromBase64String(IV);
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: Could not read file from disk. Original error: " + ex.Message);
                }
            }
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;

        }

        public string Input { get; set; }
        public string Key { get; set; }
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
        public string IV { get; set; }
        public byte[] KeyBytes { get; set; }
        public byte[] IVBytes { get; set; }

        private void btnDecryptText_Click(object sender, RoutedEventArgs e)
        {
            if (!(txtToEncrypt.Text.Length < 1))
            {
                OpenFileDialog ofd = new OpenFileDialog();

                GetKeyAndIV(ofd);

                byte[] input = Convert.FromBase64String(txtToEncrypt.Text);

                txtEncrypted.Text = DecryptStringFromBytes(input, KeyBytes, IVBytes);
            }
            else
            {
                MessageBox.Show("Input moet karakters bevatten", "Error", MessageBoxButton.OK);
            }
        }

        private void btnDecryptTextFile_Click(object sender, RoutedEventArgs e)
        {
            txtToEncrypt.Clear();

            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Title = "Selecteer het bestand dat u wilt decrypteren";
            ofd.DefaultExt = ".txt";
            ofd.Filter = "Text|*.txt|All|*.*";
            ofd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            if (ofd.ShowDialog() == true)
            {
                try
                {
                    Stream myStream;
                    if ((myStream = ofd.OpenFile()) != null)
                    {
                        using (StreamReader sr = new StreamReader(myStream))
                        {
                            Input = sr.ReadToEnd();
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: Could not read file from disk. Original error: " + ex.Message);
                }
            }

            GetKeyAndIV(ofd);

            byte[] toDecrypt = Convert.FromBase64String(Input);

            txtEncrypted.Text = DecryptStringFromBytes(toDecrypt, KeyBytes, IVBytes);
        }

        private void btnClearInput_Click(object sender, RoutedEventArgs e)
        {
            txtToEncrypt.Clear();
            txtEncrypted.Clear();
        }

        private void btnClearInputRSA_Click(object sender, RoutedEventArgs e)
        {
            txtToEncryptRSA.Clear();
            txtEncryptedRSA.Clear();
        }

        private void btnEncryptTextRSA_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            GetRSAKey(ofd);

            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                try
                {

                    if (PublicKey != null)
                    {

                        rsa.FromXmlString(PublicKey);

                        var encryptedData = rsa.Encrypt(Encoding.ASCII.GetBytes(txtToEncryptRSA.Text), true);

                        txtEncryptedRSA.Text = Convert.ToBase64String(encryptedData);
                    }

                    if (PrivateKey != null)
                    {
                        rsa.FromXmlString(PrivateKey);

                        var encryptedData = rsa.Encrypt(Encoding.ASCII.GetBytes(txtToEncryptRSA.Text), true);

                        txtEncryptedRSA.Text = Convert.ToBase64String(encryptedData);
                        //byte[] resultBytes = Convert.FromBase64String(base64Encrypted);
                        //byte[] decryptedBytes = rsa.Decrypt(resultBytes, true);
                        //string decryptedData = Encoding.UTF8.GetString(decryptedBytes);

                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Input is te lang om te encrypteren: " + ex.Message, "Error", MessageBoxButton.OK);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }       

        private void btnEncryptTextFileRSA_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            GetRSAKey(ofd);
            ofd.Title = "Selecteer het bestand dat u wilt encrypteren";
            ofd.DefaultExt = ".txt";
            ofd.Filter = "Text|*.txt|All|*.*";
            ofd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            if (ofd.ShowDialog() == true)
            {
                try
                {
                    Stream myStream;
                    if ((myStream = ofd.OpenFile()) != null)
                    {
                        using (StreamReader sr = new StreamReader(myStream))
                        {
                            Input = sr.ReadToEnd();
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: Could not read file from disk. Original error: " + ex.Message);
                }
            }

            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                try
                {

                    if (PublicKey != null)
                    {

                        rsa.FromXmlString(PublicKey);

                        var encryptedData = rsa.Encrypt(Encoding.ASCII.GetBytes(Input), true);

                        txtEncryptedRSA.Text = Convert.ToBase64String(encryptedData);
                    }

                    if (PrivateKey != null)
                    {
                        rsa.FromXmlString(PrivateKey);

                        var encryptedData = rsa.Encrypt(Encoding.ASCII.GetBytes(Input), true);

                        txtEncryptedRSA.Text = Convert.ToBase64String(encryptedData);

                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Input is te lang om te encrypteren: " + ex.Message, "Error", MessageBoxButton.OK);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        private void btnDecryptTextRSA_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            // Select PRIVATE key
            ofd.DefaultExt = ".xml";
            ofd.Title = "Selecteer uw PRIVATE key";
            ofd.Filter = "XML Files (*.xml)|*.xml";
            ofd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            PublicKey = null;
            PrivateKey = null;
            if (ofd.ShowDialog() == true)
            {
                try
                {
                    Stream myStream;
                    if ((myStream = ofd.OpenFile()) != null)
                    {
                        using (StreamReader sr = new StreamReader(myStream))
                        {
                            PrivateKey = sr.ReadToEnd();
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: Could not read file from disk. Original error: " + ex.Message);
                }
            }

            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                try
                {
                    if (PrivateKey != null)
                    {
                        rsa.FromXmlString(PrivateKey);

                        var decryptedData = rsa.Decrypt(Convert.FromBase64String(txtToEncryptRSA.Text), true);

                        txtEncryptedRSA.Text = Encoding.Default.GetString(decryptedData);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: " + ex.Message, "Error", MessageBoxButton.OK);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        private void btnDecryptTextFileRSA_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            // Select PRIVATE key
            ofd.Title = "Selecteer uw PRIVATE key";
            ofd.DefaultExt = ".xml";
            ofd.Filter = "XML Files (*.xml)|*.xml";
            ofd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            PublicKey = null;
            PrivateKey = null;
            if (ofd.ShowDialog() == true)
            {
                try
                {
                    Stream myStream;
                    if ((myStream = ofd.OpenFile()) != null)
                    {
                        using (StreamReader sr = new StreamReader(myStream))
                        {
                            PrivateKey = sr.ReadToEnd();
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: Could not read file from disk. Original error: " + ex.Message);
                }
            }

            // Select file to decrypt
            ofd.Title = "Selecteer het bestand dat u wilt decrypteren";
            ofd.DefaultExt = ".txt";
            ofd.Filter = "Text|*.txt|All|*.*";
            ofd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (ofd.ShowDialog() == true)
            {
                try
                {
                    Stream myStream;
                    if ((myStream = ofd.OpenFile()) != null)
                    {
                        using (StreamReader sr = new StreamReader(myStream))
                        {
                            Input = sr.ReadToEnd();
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: Could not read file from disk. Original error: " + ex.Message);
                }
            }

            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                try
                {

                    if (PrivateKey != null)
                    {
                        rsa.FromXmlString(PrivateKey);

                        byte[] decryptedData = rsa.Decrypt(Convert.FromBase64String(Input), true);

                        txtEncryptedRSA.Text = Encoding.Default.GetString(decryptedData);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: " + ex.Message, "Error", MessageBoxButton.OK);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        } 
        
        private void GetRSAKey(OpenFileDialog ofd)
        {
            ofd.DefaultExt = ".xml";
            ofd.Filter = "XML Files (*.xml)|*.xml";
            ofd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            PublicKey = null;
            PrivateKey = null;

            string answer = CustomMessageBox.ShowYesNo("Wilt u de PUBLIC key of PRIVATE key gebruiken om te encrypteren?", "Selecteer uw key", "PUBLIC", "PRIVATE", MessageBoxImage.Question).ToString();

            if (answer == "Yes") // PUBLIC
            {
                ofd.Title = "Selecteer uw PUBLIC KEY";
                if (ofd.ShowDialog() == true)
                {
                    try
                    {
                        Stream myStream;
                        if ((myStream = ofd.OpenFile()) != null)
                        {
                            using (StreamReader sr = new StreamReader(myStream))
                            {
                                PublicKey = sr.ReadToEnd();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Error: Could not read file from disk. Original error: " + ex.Message);
                    }
                }
            }
            else if (answer == "No") // PRIVATE
            {
                ofd.Title = "Selecteer uw PRIVATE KEY";
                if (ofd.ShowDialog() == true)
                {
                    try
                    {
                        Stream myStream;
                        if ((myStream = ofd.OpenFile()) != null)
                        {
                            using (StreamReader sr = new StreamReader(myStream))
                            {
                                PrivateKey = sr.ReadToEnd();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Error: Could not read file from disk. Original error: " + ex.Message);
                    }
                }
            }
        }
    }
}
