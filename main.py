from tkinter import *
from tkinter import messagebox
import base64
import os

def encrypt():
    password=code.get()
    if password=="1234":
       screen1=Toplevel(screen)
       screen1.title("encryption")
       screen1.geometry("400x200")
       screen1.configure(bg="#ed3833")
       message=text1.get(1.0,END)
       encode_message=message.encode("ascii")
       base64_byte=base64.b64encode(encode_message)
       encrypt=base64_byte.decode("ascii")
       Label(screen1,text="ENCRYPT",font="arial",fg="white",bg="#ed3833").place(x=10,y=0)
       text2=Text(screen1,font="lucida 15",bg="white",relief=GROOVE,wrap=WORD,bd=0)
       text2.place(x=10,y=40, width=380,height=150)
       text2.insert(END,encrypt)

    elif password=="":
         messagebox.showerror("encryptin ","input password ")
    elif password!="1234":
        messagebox.showerror("encryption","Invalid Password")

import base64
from tkinter import Toplevel, Text, Label, GROOVE, WORD, END, messagebox

def decrypt():
    password = code.get()  # Get the password from input
    if password == "1234":
        try:
            # Create new window for decryption result
            screen2 = Toplevel(screen)
            screen2.title("Decryption")
            screen2.geometry("400x200")
            screen2.configure(bg="yellow")
            
            # Get the encoded message from text1 (assuming 'text1' is a Text widget)
            message = text1.get(1.0, END).strip()  # Remove any leading/trailing newlines
            
            # Decode the base64 message
            base64_bytes = message.encode('ascii')  # Convert the message to bytes
            decoded_bytes = base64.b64decode(base64_bytes)  # Base64 decode
            
            # Convert the decoded bytes back to a string
            decrypted_message = decoded_bytes.decode('ascii')
            
            # Display the decrypted message
            Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
            text2 = Text(screen2, font="lucida 15", bg="white", relief=GROOVE, wrap=WORD, bd=0)
            text2.place(x=10, y=40, width=380, height=150)
            text2.insert(END, decrypted_message)

        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred: {str(e)}")

    elif password == "":
        messagebox.showerror("Decryption", "Input password")
    else:
        messagebox.showerror("Decryption", "Invalid Password")



def main_screen():
    global screen
    global code
    global text1
    screen=Tk()
    screen.geometry("375x400")
    #icon
    image_icon=PhotoImage(file="flowwe2.png")
    screen.iconphoto(False,image_icon)
    screen.title("Secret communication")
    
    def reset():
       code.set("")
       text1.delete(1.0,END)


    Label(text="Enter text for Encription and decription",fg="black",font="lucida 15 bold").place(x=10,y=10)
    text1=Text(font="lucida 15",bg="pink",relief=GROOVE,wrap=WORD,bd=0)
    text1.place(x=20,y=50,height=100,width=600)

    Label(text="Enter secret key for encription and decription",fg="green",bg="yellow",font="lucida 15").place(x=10,y=200)
    code=StringVar()
    Entry(textvariable=code,width=19,bd=0,bg="light grey",font=("arial",25),show="*").place(x=10,y=250)

    Button(text="ENCRYPT",height="2",width="20",bg="#ed8333",fg="#000",font="lucida 10 bold",bd=0,command=encrypt).place(x=10,y=300)
    Button(text="DECRYPT",height="2",width="20",bg="#00bd56",fg="#000",font="lucida 10 bold",bd=0,command=decrypt).place(x=250,y=300)
    Button(text="RESET",height="2",width="50",bg="#1089ff",fg="#000",bd=0,font="lucida 10 bold",command=reset).place(x=10,y=350)

    screen.mainloop()


main_screen()