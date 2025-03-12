from tkinter import *
from tkinter import messagebox
import base64
import tkinter as tk

def encrypt():
    password = code.get()

    if password == "2004":
        screen2 = Toplevel(screen)
        screen2.title("Encryption")
        screen2.geometry("400x200")
        screen2.configure(bg="#ed3833")

        message = text1.get(1.0, END)
        encode_message = message.encode("ascii")
        base64_bytes = base64.b64encode(encode_message)
        encrypted_message = base64_bytes.decode("ascii")

        Label(screen2, text="ENCRYPTED", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
        text2 = Text(screen2, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)

        text2.insert(END, encrypted_message)

    elif password == "":
        messagebox.showerror("Encryption", "Input Password")

    else:
        messagebox.showerror("Encryption", "Invalid Password")

def decrypt():
    password = code.get()

    if password == "2004":
        screen2 = Toplevel(screen)
        screen2.title("Decryption")
        screen2.geometry("400x200")
        screen2.configure(bg="#00bd56")

        message = text1.get(1.0, END)
        decode_message = message.encode("ascii")
        base64_bytes = base64.b64decode(decode_message)
        decrypted_message = base64_bytes.decode("ascii")

        Label(screen2, text="DECRYPTED", font="arial", fg="white", bg="#00bd56").place(x=10, y=0)
        text2 = Text(screen2, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10, y=40, width=380, height=150)

        text2.insert(END, decrypted_message)

    elif password == "":
        messagebox.showerror("Decryption", "Input Password")

    else:
        messagebox.showerror("Decryption", "Invalid Password")

def reset():
    code.set("")
    text1.delete(1.0, END)

def show_methods():
    screen3 = Toplevel(screen)
    screen3.title("Advanced Encryption")
    screen3.geometry("500x600")

    Label(screen3, text="Enter your message:", font=("Arial", 12)).pack(pady=5)
    text_input = Text(screen3, height=5, width=50, font=("Arial", 12))
    text_input.pack(pady=5)

    Label(screen3, text="Enter shift key (integer) for Caesar Cipher:", font=("Arial", 12)).pack(pady=5)
    shift_key = Entry(screen3, font=("Arial", 12), width=20)
    shift_key.pack(pady=5)

    Label(screen3, text="Enter password:", font=("Arial", 12)).pack(pady=5)
    advanced_code = Entry(screen3, font=("Arial", 12), width=20, show="*")
    advanced_code.pack(pady=5)

    result_box = Text(screen3, height=5, width=50, font=("Arial", 12), bg="#f1f1f1")
    result_box.pack(pady=5)

    def advanced_encrypt():
        password = advanced_code.get()
        if password == "2004":
            text = text_input.get("1.0", END).strip()
            if not text:
                messagebox.showerror("Error", "Please enter a message.")
                return

            shift = shift_key.get()
            if shift:
                try:
                    shift = int(shift)
                    encrypted_text = caesar_cipher_encrypt(text, shift)
                    result_box.delete("1.0", END)
                    result_box.insert(END, encrypted_text)
                except ValueError:
                    messagebox.showerror("Error", "Shift key must be an integer.")
            else:
                encrypted_text = base64_encrypt(text)
                result_box.delete("1.0", END)
                result_box.insert(END, encrypted_text)
        else:
            messagebox.showerror("Error", "Invalid password.")

    def advanced_decrypt():
        password = advanced_code.get()
        if password == "2004":
            text = text_input.get("1.0", END).strip()
            if not text:
                messagebox.showerror("Error", "Please enter a message.")
                return

            shift = shift_key.get()
            if shift:
                try:
                    shift = int(shift)
                    decrypted_text = caesar_cipher_decrypt(text, shift)
                    result_box.delete("1.0", END)
                    result_box.insert(END, decrypted_text)
                except ValueError:
                    messagebox.showerror("Error", "Shift key must be an integer.")
            else:
                decrypted_text = base64_decrypt(text)
                result_box.delete("1.0", END)
                result_box.insert(END, decrypted_text)
        else:
            messagebox.showerror("Error", "Invalid password.")

    def reset_fields():
        text_input.delete("1.0", END)
        result_box.delete("1.0", END)
        advanced_code.delete(0, END)
        shift_key.delete(0, END)

    Button(screen3, text="Encrypt", font=("Arial", 12), bg="#4caf50", fg="white", command=advanced_encrypt).pack(pady=10)
    Button(screen3, text="Decrypt", font=("Arial", 12), bg="#f44336", fg="white", command=advanced_decrypt).pack(pady=10)
    Button(screen3, text="Reset", font=("Arial", 12), bg="#1089ff", fg="white", command=reset_fields).pack(pady=10)

def caesar_cipher_encrypt(text, shift):
    encrypted = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

def base64_encrypt(text):
    encode_message = text.encode("ascii")
    base64_bytes = base64.b64encode(encode_message)
    return base64_bytes.decode("ascii")

def base64_decrypt(text):
    decode_message = text.encode("ascii")
    base64_bytes = base64.b64decode(decode_message)
    return base64_bytes.decode("ascii")

def run_code2_gui():
    def decrypt():
        text = input_text.get("1.0", tk.END).strip()
        shift = int(shift_entry.get())
        if not text:
            messagebox.showerror("Input Error", "Please enter text to decrypt.")
            return
        caesar_decrypted = caesar_cipher_decrypt(text, shift)
        base64_decoded = base64_decrypt(caesar_decrypted)
        if base64_decoded is not None:
            result_text.delete("1.0", tk.END)
            result_text.insert(tk.END, base64_decoded)

    gui = tk.Toplevel(screen)
    gui.title("Decryption Tool")

    # Input Text
    input_label = tk.Label(gui, text="Enter Text:")
    input_label.pack(pady=5)
    input_text = tk.Text(gui, height=5, width=50)
    input_text.pack(pady=5)

    # Shift Key
    shift_label = tk.Label(gui, text="Enter Shift Key (for Caesar Cipher):")
    shift_label.pack(pady=5)
    shift_entry = tk.Entry(gui)
    shift_entry.pack(pady=5)

    # Decrypt Button
    decrypt_button = tk.Button(gui, text="Decrypt", command=decrypt, bg="#4caf50", fg="white", font=("Arial", 12), width=20, height=2)
    decrypt_button.pack(pady=10)

    # Result Text
    result_label = tk.Label(gui, text="Result:")
    result_label.pack(pady=5)
    result_text = tk.Text(gui, height=5, width=50)
    result_text.pack(pady=5)

def main_screen():
    global screen
    global code
    global text1

    screen = Tk()
    screen.geometry("375x450")

    # icon
    image_icon = PhotoImage(file="penguin.png")
    screen.iconphoto(False, image_icon)
    screen.title("PYATUL")

    Label(text="Enter text for Encryption/Decryption", fg="black", font=("calibri", 13)).place(x=10, y=10)
    text1 = Text(font="Roboto 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, width=355, height=100)

    Label(text="Enter secret key for Encryption/Decryption", fg="black", font=("calibri", 13)).place(x=10, y=170)

    code = StringVar()
    Entry(textvariable=code, width=19, bd=0, font=("arial", 25), show="*").place(x=10, y=200)

    Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=250)
    Button(text="DECRYPT", height="2", width=23, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=200, y=250)
    Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10, y=300)
    Button(text="ADVANCED TOOL", height="2", width=50, bg="#ffa500", fg="black", bd=0, command=show_methods).place(x=10, y=350)
    Button(text="DECRYPTION TOOL", height="2", width=50, bg="#ff5722", fg="white", bd=0, command=run_code2_gui).place(x=10, y=400)

    screen.mainloop()

main_screen()
