import os
import hashlib
import tkinter as tk
from tkinter import filedialog
import re

class ScannerGUI(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.geometry('800x600')
        self.master.title("Malware Scanner with signature based")
        self.pack(expand=True, fill=tk.BOTH)
        self.create_widgets()

    def create_widgets(self):
        # Create the input widgets
        input_frame = tk.Frame(self, bg='#C6E2FF')
        input_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        path_label = tk.Label(input_frame, text="File Path:", bg='#C6E2FF')
        path_label.pack(side=tk.LEFT)

        self.path_entry = tk.Entry(input_frame)
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)

        path_button = tk.Button(input_frame, text="Browse", command=self.browse_file)
        path_button.pack(side=tk.LEFT, padx=10)

        scan_button = tk.Button(input_frame, text="Scan", command=self.scan_file)
        scan_button.pack(side=tk.LEFT, padx=10)

        # Create the output widgets
        output_frame = tk.Frame(self, bg='#FFF9C4')
        output_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        result_label = tk.Label(output_frame, text="Results:", font=("Arial Bold", 14), bg='#FFF9C4')
        result_label.pack(side=tk.TOP, pady=10)

        scrollbar = tk.Scrollbar(output_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.result_listbox = tk.Listbox(output_frame, font=("Arial", 12), yscrollcommand=scrollbar.set)
        self.result_listbox.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar.config(command=self.result_listbox.yview)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.path_entry.delete(0, tk.END)
        self.path_entry.insert(0, file_path)

    def load_signatures(self):
        with open('full_sha256.txt', 'r') as f:
            lines = f.readlines()
        return set(line.strip() for line in lines)

    def scan_file(self):
        file_path = self.path_entry.get()
        if not file_path:
            return

        signatures = self.load_signatures()
        self.result_listbox.delete(0, tk.END)
        try:
            # Check if the file exists
            if not os.path.exists(file_path):
                result = f"File {file_path} not found."
            else:
                # Compute SHA256 hash of the file
                with open(file_path, "rb") as f:
                    content = f.read()
                    sha_256 = hashlib.sha256(content).hexdigest()

                # Check if the computed hash is in the set of signatures
                if sha_256 in signatures:
                    result = f"{file_path} is a malicious malware!"
                else:
                    result = f"{file_path} is clean."
        except Exception as e:
            result = f"Error while scanning file {file_path}: {e}"
        finally:
            self.result_listbox.insert(tk.END, result)

root = tk.Tk()
root.configure(bg='#C6E2FF')
app = ScannerGUI(master=root)
app.mainloop()
