import tkinter as tk
from tkinter import messagebox
import cv2
from PIL import Image, ImageTk
import threading, socket, os
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import firebase_admin
from firebase_admin import credentials, db

# Firebase setup
cred = credentials.Certificate("/home/marwah555/final/serviceAccountKey.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://ece4301-finaldatabase-default-rtdb.firebaseio.com/',
    'databaseAuthVariableOverride': None 
})

# AES setup
key = b'0123456789abcdef0123456789abcdef'
aesgcm = AESGCM(key)

class ReceiverGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Camera Receiver")
        self.root.geometry("720x580")

        self.status_label = tk.Label(root, text="🔴 Status: Not Connected", fg="red", font=("Arial", 14))
        self.status_label.pack(pady=10)

        self.canvas = tk.Canvas(root, width=640, height=480)
        self.canvas.pack()

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)

        self.start_btn = tk.Button(btn_frame, text="Start Stream", command=self.start_stream)
        self.start_btn.grid(row=0, column=0, padx=10)

        self.stop_btn = tk.Button(btn_frame, text="Stop Stream", command=self.stop_stream)
        self.stop_btn.grid(row=0, column=1, padx=10)

        self.snapshot_btn = tk.Button(btn_frame, text="Save Snapshot", command=self.save_snapshot)
        self.snapshot_btn.grid(row=0, column=2, padx=10)

        self.current_frame = None
        self.running = False
        self.sock_thread = None

    def update_status(self, connected):
        if connected:
            self.status_label.config(text="🟢 Status: Connected", fg="green")
        else:
            self.status_label.config(text="🔴 Status: Not Connected", fg="red")

    def start_stream(self):
        if not self.running:
            try:
                db.reference('stream_command').set('start')
                self.running = True
                self.sock_thread = threading.Thread(target=self.receive_video, daemon=True)
                self.sock_thread.start()
            except Exception as e:
                messagebox.showerror("Firebase Error", str(e))
        else:
            messagebox.showinfo("Info", "Stream is already running.")

    def stop_stream(self):
        if self.running:
            db.reference('stream_command').set('stop')
            self.running = False
            self.update_status(False)
            print("Stream stopped.")
        else:
            messagebox.showinfo("Info", "Stream is not running.")

    def save_snapshot(self):
        if self.current_frame is not None:
            cv2.imwrite("snapshot.jpg", self.current_frame)
            messagebox.showinfo("Snapshot", "Image saved as snapshot.jpg")

    def receive_video(self):
        host = '0.0.0.0'
        port = 15672
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((host, port))
            server.listen(1)
            print("Waiting for incoming connection...")
            conn, addr = server.accept()
            print(f"Connected from {addr}")
            self.update_status(True)
    
            while self.running:
                length_data = conn.recv(4)
                if not length_data:
                    break
                length = int.from_bytes(length_data, 'big')
                packet = b''
                while len(packet) < length:
                    chunk = sock.recv(length - len(packet))
                    if not chunk:
                        raise ConnectionError("Socket closed unexpectedly during recv.")
                    packet += chunk

    
                nonce = packet[:12]
                ciphertext = packet[12:]
                data = aesgcm.decrypt(nonce, ciphertext, None)
                frame = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
                self.current_frame = frame
                img = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                img = Image.fromarray(img)
                imgtk = ImageTk.PhotoImage(image=img)
                self.canvas.create_image(0, 0, anchor=tk.NW, image=imgtk)
                self.canvas.imgtk = imgtk
    
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}", fg="red")
            print(f"Error: {str(e)}")
        finally:
            self.update_status(False)
            conn.close()
            server.close()


if __name__ == "__main__":
    root = tk.Tk()
    app = ReceiverGUI(root)
    root.mainloop()
