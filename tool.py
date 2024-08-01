import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import pywhatkit as kit
import smtplib
import random
import string
import os
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import base64
import webbrowser

# Helper functions

def generate_password(length=32):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def encrypt_image(file_path, password):
    key = base64.urlsafe_b64encode(password.encode())
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        original = file.read()
    
    encrypted = fernet.encrypt(original)
    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    
    return encrypted_file_path

def decrypt_image(file_path, password):
    key = base64.urlsafe_b64encode(password.encode())
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        encrypted = file.read()
    
    decrypted = fernet.decrypt(encrypted)
    decrypted_file_path = file_path.replace('.encrypted', '')
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)
    
    return decrypted_file_path

def send_email(encrypted_file_path, sender_email, receiver_email, smtp_password, auto_password, subject="Encrypted Image"):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    body = f"Attached is your encrypted image. Use the following automated password to decrypt it: {auto_password}"
    msg.attach(MIMEText(body, 'plain'))

    attachment = open(encrypted_file_path, 'rb')

    part = MIMEBase('application', 'octet-stream')
    part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f"attachment; filename= {os.path.basename(encrypted_file_path)}")

    msg.attach(part)

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, smtp_password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def browse_file(entry):
    file_path = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, file_path)


def toggle_password(entry):
    if entry.cget('show') == '':
        entry.config(show='*')
    else:
        entry.config(show='')

def encrypt_and_send(file_path_entry, password_entry, sender_entry, receiver_entry, smtp_password_entry):
    file_path = file_path_entry.get()
    manual_password = password_entry.get()
    auto_password = generate_password()
    sender_email = sender_entry.get()
    receiver_email = receiver_entry.get()
    smtp_password = smtp_password_entry.get()

    if not file_path or not sender_email or not receiver_email or not smtp_password:
        messagebox.showerror("Error", "All fields are required")
        return

    try:
        password_to_use = manual_password if manual_password else auto_password
        encrypted_file_path = encrypt_image(file_path, password_to_use)
        if send_email(encrypted_file_path, sender_email, receiver_email, smtp_password, auto_password):
            messagebox.showinfo("Success", "Encrypted image sent successfully with the automated password")
        else:
            messagebox.showerror("Error", "Failed to send email")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to encrypt and send image: {e}")

def decrypt_and_show(file_path_entry, password_entry, auto_password_entry, window):
    file_path = file_path_entry.get()
    password = password_entry.get()
    auto_password = auto_password_entry.get()

    if not file_path or not password or not auto_password:
        messagebox.showerror("Error", "All fields are required")
        return

    try:
        decrypted_file_path = decrypt_image(file_path, password)
        if password == auto_password:  # Check if passwords match
            decrypted_image = Image.open(decrypted_file_path)
            decrypted_image.show()
        else:
            messagebox.showerror("Error", "Wrong automated password check your mail ")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt image: {e}")


class EncryptDecryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption and Decryption Tool")
        self.root.configure(bg='grey')


        self.canvas = tk.Canvas(root, bg='gray',width=900, height=0.1)
        self.canvas.pack(fill=tk.BOTH, expand=True)



        # Load the background image
        self.background_image = Image.open(r"C:\Users\HP\OneDrive\Pictures\bg3.jpg")
        self.background_photo = ImageTk.PhotoImage(self.background_image)



        # Create a Canvas widget
        self.canvas = tk.Canvas(self.root, width=self.background_image.width, height=self.background_image.height)
        self.canvas.pack(fill="both", expand=True)
        

        # Set the background image
        self.canvas.create_image(0,0, image=self.background_photo, anchor="nw")


       


        # heading

        heading = tk.Label(root, text="Image Encryption with Advanced Encryption",bg='skyblue',fg='black',font=("Arial", 16))
        self.canvas.create_window(self.background_image.width // 2, 40, window=heading)



        #project info

        self.project_info_button = tk.Button(self.root, text="Project Info", command=self.project_info, bg='blue',fg='white')
        self.canvas.create_window(self.background_image.width // 2, 100, window=self.project_info_button)
        


        # Load and resize the lock icon image
        image_path = r"C:\Users\HP\Downloads\—Pngtree—3d lock icon cyber security_15523015 (2).png"
        img = Image.open(image_path)
        img = img.resize((120,120), Image.LANCZOS)
        self.lock_image = ImageTk.PhotoImage(img)

        
         # Initially place the image below the Project Info button
        self.image_id = self.canvas.create_image(self.canvas.winfo_reqwidth() // 2, 190, image=self.lock_image, anchor=tk.CENTER)

        # Bind the configure event to update the positions
        self.root.bind('<Configure>', self.update_positions)



        self.user_guide_button = tk.Button(self.root, text="User Guide", command=self.user_guide, bg='blue',fg='white')
        self.canvas.create_window(self.background_image.width // 2, 265, window=self.user_guide_button)

        self.encrypt_button = tk.Button(self.root, text="Encrypt", command=self.create_encrypt_window, bg='blue',fg='white')
        self.canvas.create_window(self.background_image.width // 2, 325, window=self.encrypt_button)

        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.create_decrypt_window, bg='blue',fg='white')
        self.canvas.create_window(self.background_image.width // 2, 385, window=self.decrypt_button)



        self.advanced_options_button = tk.Button(self.root, text="Advanced Options", command=self.open_advanced_options, bg='blue',fg='white')
        self.canvas.create_window(self.background_image.width // 2, 435, window=self.advanced_options_button)

    def update_positions(self, event=None):
        # Update image position below the Project Info button
        self.canvas.coords(self.image_id, self.background_image.width // 2, 185)






    def create_encrypt_window(self):
        encrypt_window = tk.Toplevel(self.root)
        encrypt_window.title("Encrypt Image")
        encrypt_window.configure(bg='grey')

        file_path_label = tk.Label(encrypt_window, text="File Path:", bg='grey')
        file_path_label.grid(row=0, column=0, padx=10, pady=10)
        file_path_entry = tk.Entry(encrypt_window, width=50)
        file_path_entry.grid(row=0, column=1, padx=10, pady=10)
        browse_button = tk.Button(encrypt_window, text="Browse", command=lambda: browse_file(file_path_entry), bg='blue', fg='white')
        browse_button.grid(row=0, column=2, padx=10, pady=10)

        password_label = tk.Label(encrypt_window, text="Manual Password:", bg='grey')
        password_label.grid(row=1, column=0, padx=10, pady=10)
        password_entry = tk.Entry(encrypt_window, show='*', width=50)
        password_entry.grid(row=1, column=1, padx=10, pady=10)
        toggle_button = tk.Button(encrypt_window, text="Show", command=lambda: toggle_password(password_entry), bg='blue', fg='white')
        toggle_button.grid(row=1, column=2, padx=10, pady=10)

        sender_label = tk.Label(encrypt_window, text="Sender Email:", bg='grey')
        sender_label.grid(row=2, column=0, padx=10, pady=10)
        sender_entry = tk.Entry(encrypt_window,show='*',width=50)
        sender_entry.grid(row=2, column=1, padx=10, pady=10)
        toggle_button = tk.Button(encrypt_window, text="Show", command=lambda: toggle_password(sender_entry), bg='blue', fg='white')
        toggle_button.grid(row=2, column=2, padx=10, pady=10)



        receiver_label = tk.Label(encrypt_window, text="Receiver Email:", bg='grey')
        receiver_label.grid(row=3, column=0, padx=10, pady=10)
        receiver_entry = tk.Entry(encrypt_window, show='*', width=50)
        receiver_entry.grid(row=3, column=1, padx=10, pady=10)
        toggle_button = tk.Button(encrypt_window, text="Show", command=lambda: toggle_password(receiver_entry), bg='blue', fg='white')
        toggle_button.grid(row=3, column=2, padx=10, pady=10)


        smtp_password_label = tk.Label(encrypt_window, text="SMTP Password:", bg='grey')
        smtp_password_label.grid(row=4, column=0, padx=10, pady=10)
        smtp_password_entry = tk.Entry(encrypt_window, show='*', width=50)
        smtp_password_entry.grid(row=4, column=1, padx=10, pady=10)
        smtp_toggle_button = tk.Button(encrypt_window, text="Show", command=lambda: toggle_password(smtp_password_entry), bg='blue', fg='white')
        smtp_toggle_button.grid(row=4, column=2, padx=10, pady=10)

        encrypt_button = tk.Button(encrypt_window, text="Encrypt and Send", command=lambda: encrypt_and_send(file_path_entry, password_entry, sender_entry, receiver_entry, smtp_password_entry), bg='blue', fg='white')
        encrypt_button.grid(row=5, column=1, padx=10, pady=10)

    def create_decrypt_window(self):
        decrypt_window = tk.Toplevel(self.root)
        decrypt_window.title("Decrypt Image")
        decrypt_window.configure(bg='grey')

        file_path_label = tk.Label(decrypt_window, text="File Path:", bg='grey')
        file_path_label.grid(row=0, column=0, padx=10, pady=10)
        file_path_entry = tk.Entry(decrypt_window,width=50)
        file_path_entry.grid(row=0, column=1, padx=10, pady=10)
        browse_button = tk.Button(decrypt_window, text="Browse", command=lambda: browse_file(file_path_entry), bg='blue', fg='white')
        browse_button.grid(row=0, column=2, padx=10, pady=10)



        password_label = tk.Label(decrypt_window, text="Password:", bg='grey')
        password_label.grid(row=1, column=0, padx=10, pady=10)
        password_entry = tk.Entry(decrypt_window, show='*', width=50)
        password_entry.grid(row=1, column=1, padx=10, pady=10)
        toggle_button = tk.Button(decrypt_window, text="Show", command=lambda: toggle_password(password_entry), bg='blue', fg='white')
        toggle_button.grid(row=1, column=2, padx=10, pady=10)

        auto_password_label = tk.Label(decrypt_window, text="Auto Password:", bg='grey')
        auto_password_label.grid(row=2, column=0, padx=10, pady=10)
        auto_password_entry = tk.Entry(decrypt_window, show='*', width=50)
        auto_password_entry.grid(row=2, column=1, padx=10, pady=10)
        auto_toggle_button = tk.Button(decrypt_window, text="Show", command=lambda: toggle_password(auto_password_entry), bg='blue', fg='white')
        auto_toggle_button.grid(row=2, column=2, padx=10, pady=10)

        decrypt_button = tk.Button(decrypt_window, text="Decrypt and Show", command=lambda: decrypt_and_show(file_path_entry, password_entry, auto_password_entry, decrypt_window), bg='blue', fg='white')
        decrypt_button.grid(row=3, column=1, padx=10, pady=10)




    def open_advanced_options(self):
        advanced_options_window = tk.Toplevel(self.root)
        advanced_options_window.title("Advanced Options")
        advanced_options_window.configure(bg='grey')


        encrypt_button = tk.Button(advanced_options_window, text="Encrypt", command=self.open_advanced_encrypt_a, bg='blue',fg='white')
        encrypt_button.pack(pady=10)
        

        decrypt_button = tk.Button(advanced_options_window, text="Decrypt", command=lambda: self.open_advanced_decrypt_a(advanced_options_window), bg='blue',fg='white')
        decrypt_button.pack(pady=10)
       
   



    def browse_file_a(self):
        file_path = filedialog.askopenfilename()
        self.file_path_entry.insert(0, file_path)



    def open_advanced_encrypt_a(self):
        advanced_encrypt_window = tk.Toplevel(self.root)
        advanced_encrypt_window.title("Advanced Encrypt")
        advanced_encrypt_window.configure(bg='grey')

        tk.Label(advanced_encrypt_window, text="File Path:", bg='grey').grid(row=0, column=0, padx=10, pady=10)
        self.file_path_entry = tk.Entry(advanced_encrypt_window, width=50)
        self.file_path_entry.grid(row=0, column=1, padx=10, pady=10)
        tk.Button(advanced_encrypt_window, text="Browse", command=self.browse_file_a, bg='blue',fg='white').grid(row=0, column=2, padx=10, pady=10)

        tk.Label(advanced_encrypt_window, text="Sender's Email:", bg='grey').grid(row=1, column=0, padx=10, pady=10)
        self.sender_email_entry = tk.Entry(advanced_encrypt_window, show='*', width=50)
        self.sender_email_entry.grid(row=1, column=1, padx=10, pady=10)

        tk.Label(advanced_encrypt_window, text="SMTP Password:", bg='grey').grid(row=2, column=0, padx=10, pady=10)
        self.smtp_password_entry = tk.Entry(advanced_encrypt_window, show="*", width=50)
        self.smtp_password_entry.grid(row=2, column=1, padx=10, pady=10)

        tk.Label(advanced_encrypt_window, text="Receiver's Email:", bg='grey').grid(row=3, column=0, padx=10, pady=10)
        self.receiver_email_entry = tk.Entry(advanced_encrypt_window,show='*', width=50)
        self.receiver_email_entry.grid(row=3, column=1, padx=10, pady=10)

        tk.Label(advanced_encrypt_window, text="WhatsApp Number:", bg='grey').grid(row=4, column=0, padx=10, pady=10)
        self.whatsapp_number_entry = tk.Entry(advanced_encrypt_window, show='*',width=50)
        self.whatsapp_number_entry.grid(row=4, column=1, padx=10, pady=10)

        tk.Button(advanced_encrypt_window, text="Encrypt", command=self.encrypt_image_a, bg='blue',fg='white').grid(row=5, column=1, pady=10)



     
    def open_advanced_decrypt_a(self, parent_window):
        advanced_decrypt_window = tk.Toplevel(parent_window)
        advanced_decrypt_window.title("Advanced Decrypt")
        advanced_decrypt_window.configure(bg='grey')

        tk.Label(advanced_decrypt_window, text="File Path:", bg='grey').grid(row=0, column=0, padx=10, pady=10)
        self.decrypt_file_path_entry = tk.Entry(advanced_decrypt_window, width=50)
        self.decrypt_file_path_entry.grid(row=0, column=1, padx=10, pady=10)
        tk.Button(advanced_decrypt_window, text="Browse", command=self.browse_decrypt_file, bg='blue',fg='white').grid(row=0, column=2, padx=10, pady=10)

        tk.Label(advanced_decrypt_window, text="Automated Password:", bg='grey').grid(row=1, column=0, padx=10, pady=10)
        self.automated_password_entry = tk.Entry(advanced_decrypt_window, show="*", width=50)
        self.automated_password_entry.grid(row=1, column=1, padx=10, pady=10)

        tk.Label(advanced_decrypt_window, text="Decryptors's Email:", bg='grey').grid(row=2, column=0, padx=10, pady=10)
        self.decrypt_sender_email_entry = tk.Entry(advanced_decrypt_window,show='*', width=50)
        self.decrypt_sender_email_entry.grid(row=2, column=1, padx=10, pady=10)

        tk.Label(advanced_decrypt_window, text="Encryptor's Email:", bg='grey').grid(row=3, column=0, padx=10, pady=10)
        self.decrypt_receiver_email_entry = tk.Entry(advanced_decrypt_window,show='*',width=50)
        self.decrypt_receiver_email_entry.grid(row=3, column=1, padx=10, pady=10)

        tk.Label(advanced_decrypt_window, text="SMTP Password:", bg='grey').grid(row=4, column=0, padx=10, pady=10)
        self.decrypt_smtp_password_entry = tk.Entry(advanced_decrypt_window, show="*", width=50)
        self.decrypt_smtp_password_entry.grid(row=4, column=1, padx=10, pady=10)

        tk.Button(advanced_decrypt_window, text="Request Decrypt", command=lambda: self.request_decrypt(advanced_decrypt_window), bg='blue',fg='white').grid(row=5, column=1, pady=10)

    



    def encrypt_image_a(self):
        file_path = self.file_path_entry.get()
        sender_email = self.sender_email_entry.get()
        smtp_password = self.smtp_password_entry.get()
        receiver_email = self.receiver_email_entry.get()
        whatsapp_number = self.whatsapp_number_entry.get()

        # Encryption logic
        encrypted_image_path = file_path + ".enc"
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted_data = data[::-1]  # Simple reversal encryption
        with open(encrypted_image_path, 'wb') as f:
            f.write(encrypted_data)

        # Send encrypted image as email attachment
        self.send_email_a(sender_email, smtp_password, receiver_email, encrypted_image_path)

        # Send automated password to WhatsApp
        self.automated_password = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        kit.sendwhatmsg_instantly(f"+{whatsapp_number}", f"Your encryption password is: {self.automated_password}")

        messagebox.showinfo("Encryption", "Image encrypted and sent successfully!")




    def browse_decrypt_file(self):
        file_path = filedialog.askopenfilename()
        self.decrypt_file_path_entry.insert(0, file_path)




    def send_email_a(self, sender_email, smtp_password, receiver_email, attachment_path):
        subject = "Encrypted Image"
        body = "Please find the encrypted image attached."

        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject

        message.attach(MIMEText(body, "plain"))

        with open(attachment_path, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename= {os.path.basename(attachment_path)}")

            message.attach(part)

        text = message.as_string()

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, smtp_password)
            server.sendmail(sender_email, receiver_email, text)


    def request_decrypt(self, advanced_decrypt_window):
        sender_email = self.decrypt_sender_email_entry.get()
        smtp_password = self.decrypt_smtp_password_entry.get()
        receiver_email = self.decrypt_receiver_email_entry.get()
        automated_password = self.automated_password_entry.get()

        if  self.automated_password_entry!= self.automated_password_entry:
            messagebox.showerror("Error", "Incorrect automated password.")
            return

        self.confirmation_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

        subject = "Decryption Confirmation Code"
        body = f"Your decryption confirmation code is: {self.confirmation_code}"
        message = f"Subject: {subject}\n\n{body}"

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, smtp_password)
            server.sendmail(sender_email, receiver_email, message)

        tk.Label(advanced_decrypt_window, text="Enter Confirmation Code:", bg='grey',fg='white').grid(row=6, column=0, padx=10, pady=10)
        self.confirmation_code_entry = tk.Entry(advanced_decrypt_window, show="*", width=50)
        self.confirmation_code_entry.grid(row=6, column=1, padx=10, pady=10)

        tk.Button(advanced_decrypt_window, text="Confirm Decrypt", command=lambda: self.confirm_decrypt(advanced_decrypt_window), bg='blue',fg='white').grid(row=7, column=1, pady=10)

    def confirm_decrypt(self, advanced_decrypt_window):
        entered_code = self.confirmation_code_entry.get()
        if entered_code == self.confirmation_code:
            file_path = self.decrypt_file_path_entry.get()
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = encrypted_data[::-1]  # Simple reversal decryption

            decrypted_image_path = file_path.replace(".enc", ".dec")
            with open(decrypted_image_path, 'wb') as f:
                f.write(decrypted_data)

            # Display decrypted image in the advanced decrypt window
            try:
                image = Image.open(decrypted_image_path)
                image = image.resize((400, 400))
                img = ImageTk.PhotoImage(image)

                img_label = tk.Label(advanced_decrypt_window, image=img)
                img_label.image = img  # Keep a reference to avoid garbage collection
                img_label.grid(row=8, columnspan=3, padx=10, pady=10)

                messagebox.showinfo("Decryption", "Image decrypted successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open decrypted image: {e}")
        else:
            messagebox.showerror("Error", "Incorrect confirmation code.")





    def project_info(self):
        html_file_path = r'C:\Users\HP\OneDrive\Desktop\project_info.html'
        webbrowser.open(html_file_path)

    def user_guide(self):
        """Show user guide video."""
        user_guide_window = tk.Toplevel()
        user_guide_window.title("User Guide")

        description = ScrolledText(user_guide_window, wrap=tk.WORD, width=60, height=15,bg='lightblue')
        description.pack(pady=10)
        description.insert(tk.END, "This tool allows you to encrypt and decrypt images with Advanced Features. Follow the steps below:\n\n"

                                    "1.To encrypt an image, click on the 'Encrypt' button and follow the instructions and Secure your images with strong encryption.\n"
                                    "2.To decrypt an image, click on the 'Decrypt' button and follow the instructions and decrypt the image with ease.\n"   
                                    "3.Advanced Options: Utilize enhanced functionalities for more control over encryption and decryption and for additional security features.\n"
                                    "4.Approval and Viewing: Request decryption approval and view decrypted images seamlessly.\n"
                                    "5. You can find a detailed user guide video below.\n"
                                    "6.Click on 'Play Video' button and Watch the Video Provided to Know how to use this tool ")

        play_video_button = tk.Button(user_guide_window, text="Play Video", command=self.play_user_guide_video,bg='blue',fg='white')
        play_video_button.pack(pady=5)

    def play_user_guide_video(self):
        """Play the user guide video."""
        user_guide_path = r'C:\Users\HP\OneDrive\Pictures\naaaa.mp4'
        if os.path.exists(user_guide_path):
            os.startfile(user_guide_path)
        else:
            messagebox.showerror("Error", "User guide video not found.")

    


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptDecryptApp(root)
    root.mainloop()
