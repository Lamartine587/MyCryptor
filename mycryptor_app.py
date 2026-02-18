import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import psycopg2
import base64
import os
import sys
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# --- 1. CONFIGURATION & PATH HELPER ---
def get_resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


# Load .env file
env_path = get_resource_path(".env")
load_dotenv(dotenv_path=env_path)

DB_CONNECTION_STRING = os.getenv("DB_URL")
SALT_HEX = os.getenv("MY_SALT")

# Validation
if not DB_CONNECTION_STRING or not SALT_HEX:
    # We use a primitive tk root just to show the error before crashing
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Config Error", "Missing DB_URL or MY_SALT in .env file!")
    exit()

try:
    FIXED_SALT = bytes.fromhex(SALT_HEX)
except ValueError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Config Error", "MY_SALT in .env is not valid Hex!")
    exit()


# --- 2. CRYPTO CORE ---
class CryptoManager:
    def __init__(self, master_password):
        self.salt = FIXED_SALT
        self.key = self._derive_key(master_password, self.salt)
        self.fernet = Fernet(self.key)

    def _derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt(self, data):
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, token):
        try:
            return self.fernet.decrypt(token.encode()).decode()
        except Exception:
            return None


# --- 3. DATABASE MANAGER ---
class DBManager:
    def __init__(self):
        self.conn = None
        try:
            self.conn = psycopg2.connect(DB_CONNECTION_STRING)
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to NeonDB: {e}")

    def save_entry(self, account_name, encrypted_pass):
        if not self.conn: return False
        try:
            with self.conn.cursor() as cur:
                # Upsert: Insert or Update if exists
                query = """
                    INSERT INTO sys_logs_v2 (log_id, trace_data) 
                    VALUES (%s, %s)
                    ON CONFLICT (log_id) 
                    DO UPDATE SET trace_data = EXCLUDED.trace_data;
                """
                cur.execute(query, (account_name, encrypted_pass))
                self.conn.commit()
                return True
        except Exception as e:
            messagebox.showerror("DB Error", str(e))
            return False

    def fetch_all(self):
        if not self.conn: return []
        try:
            with self.conn.cursor() as cur:
                cur.execute("SELECT log_id, trace_data FROM sys_logs_v2 ORDER BY log_id ASC")
                return cur.fetchall()
        except Exception as e:
            messagebox.showerror("DB Error", str(e))
            return []

    def get_entry(self, account_name):
        if not self.conn: return None
        try:
            with self.conn.cursor() as cur:
                cur.execute("SELECT trace_data FROM sys_logs_v2 WHERE log_id = %s", (account_name,))
                result = cur.fetchone()
                return result[0] if result else None
        except Exception as e:
            messagebox.showerror("DB Error", str(e))
            return None


# --- 4. THEME CONFIGURATION ---
THEMES = {
    "light": {
        "bg": "#f5f5f5", "fg": "#333333",
        "entry_bg": "#ffffff", "entry_fg": "#000000",
        "btn_primary": "#2ecc71", "btn_text": "white",
        "tree_bg": "white", "tree_fg": "black",
        "tree_row_even": "#f0f0f0", "tree_row_odd": "white"
    },
    "dark": {
        "bg": "#2b2b2b", "fg": "#ecf0f1",
        "entry_bg": "#404040", "entry_fg": "#ffffff",
        "btn_primary": "#27ae60", "btn_text": "white",
        "tree_bg": "#333333", "tree_fg": "white",
        "tree_row_even": "#3b3b3b", "tree_row_odd": "#333333"
    }
}


# --- 5. MAIN APPLICATION ---
class MyCryptorApp:
    def __init__(self, root, master_pass):
        self.root = root
        self.root.title("MyCryptor v3.0 - Vault Manager")
        self.root.geometry("800x600")

        # State
        self.master_pass = master_pass
        self.crypto = CryptoManager(self.master_pass)
        self.db = DBManager()
        self.current_theme = "light"

        # Widget Registries
        self.frames = []
        self.labels = []
        self.entries = []
        self.buttons = []

        self._setup_structure()
        self.apply_theme("light")

    def _setup_structure(self):
        # Main Container
        self.main_container = tk.Frame(self.root)
        self.main_container.pack(fill="both", expand=True)
        self.frames.append(self.main_container)

        # Header / Toolbar
        self.toolbar = tk.Frame(self.main_container, pady=5, padx=10)
        self.toolbar.pack(fill="x", side="top")
        self.frames.append(self.toolbar)

        self.btn_theme = tk.Button(self.toolbar, text="Toggle Theme 🌓", command=self.toggle_theme,
                                   font=("Arial", 9), cursor="hand2")
        self.btn_theme.pack(side="right")

        # Tabs
        self.tab_control = ttk.Notebook(self.main_container)
        self.tab_add = tk.Frame(self.tab_control)
        self.tab_view = tk.Frame(self.tab_control)

        self.tab_control.add(self.tab_add, text='  Add / Update  ')
        self.tab_control.add(self.tab_view, text='  My Vault  ')
        self.tab_control.pack(expand=1, fill="both")

        self.frames.append(self.tab_add)
        self.frames.append(self.tab_view)

        self._build_add_tab()
        self._build_view_tab()

        self.tab_control.bind("<<NotebookTabChanged>>", self._on_tab_change)

    def _build_add_tab(self):
        center_frame = tk.Frame(self.tab_add)
        center_frame.pack(expand=True)
        self.frames.append(center_frame)

        lbl_title = tk.Label(center_frame, text="Secure New Entry", font=("Arial", 16, "bold"))
        lbl_title.pack(pady=(0, 20))
        self.labels.append(lbl_title)

        lbl_acc = tk.Label(center_frame, text="Account Name (Alias)", font=("Arial", 10))
        lbl_acc.pack(anchor="center")
        self.labels.append(lbl_acc)

        self.entry_account = tk.Entry(center_frame, width=35, font=("Consolas", 12), justify='center')
        self.entry_account.pack(pady=5)
        self.entries.append(self.entry_account)

        lbl_pass = tk.Label(center_frame, text="Password", font=("Arial", 10))
        lbl_pass.pack(anchor="center", pady=(15, 0))
        self.labels.append(lbl_pass)

        self.entry_pass = tk.Entry(center_frame, width=35, show="*", font=("Consolas", 12), justify='center')
        self.entry_pass.pack(pady=5)
        self.entries.append(self.entry_pass)

        self.btn_save = tk.Button(center_frame, text="Encrypt & Save", command=self.do_save,
                                  font=("Arial", 12, "bold"), height=2, width=20, cursor="hand2")
        self.btn_save.pack(pady=30)
        self.buttons.append(self.btn_save)

        self.lbl_status_add = tk.Label(center_frame, text="Ready", font=("Arial", 9))
        self.lbl_status_add.pack()
        self.labels.append(self.lbl_status_add)

    def _build_view_tab(self):
        content_frame = tk.Frame(self.tab_view, padx=20, pady=20)
        content_frame.pack(fill="both", expand=True)
        self.frames.append(content_frame)

        # Treeview
        columns = ("alias", "encrypted")
        self.tree = ttk.Treeview(content_frame, columns=columns, show="headings", selectmode="browse", height=15)
        self.tree.heading("alias", text="Account Name")
        self.tree.heading("encrypted", text="Encrypted Data")

        self.tree.column("alias", width=200, anchor="center")
        self.tree.column("encrypted", width=350, anchor="center")

        scrollbar = ttk.Scrollbar(content_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="top", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Buttons
        btn_frame = tk.Frame(content_frame, pady=15)
        btn_frame.pack(fill="x")
        self.frames.append(btn_frame)

        center_btn_container = tk.Frame(btn_frame)
        center_btn_container.pack(anchor="center")
        self.frames.append(center_btn_container)

        btn_decrypt = tk.Button(center_btn_container, text="🔓 Decrypt", command=self.do_decrypt_popup, width=15)
        btn_decrypt.pack(side="left", padx=10)
        self.buttons.append(btn_decrypt)

        btn_edit = tk.Button(center_btn_container, text="✏️ Edit", command=self.do_edit_popup, width=15)
        btn_edit.pack(side="left", padx=10)
        self.buttons.append(btn_edit)

        btn_refresh = tk.Button(center_btn_container, text="🔄 Refresh", command=self.refresh_table, width=15)
        btn_refresh.pack(side="left", padx=10)
        self.buttons.append(btn_refresh)

    # --- THEME LOGIC ---
    def toggle_theme(self):
        new_theme = "dark" if self.current_theme == "light" else "light"
        self.apply_theme(new_theme)

    def apply_theme(self, theme_name):
        self.current_theme = theme_name
        t = THEMES[theme_name]

        for frame in self.frames:
            frame.config(bg=t["bg"])
        for lbl in self.labels:
            lbl.config(bg=t["bg"], fg=t["fg"])
        for entry in self.entries:
            entry.config(bg=t["entry_bg"], fg=t["entry_fg"], insertbackground=t["fg"])
        for btn in self.buttons:
            btn.config(bg=t["btn_primary"], fg=t["btn_text"], activebackground=t["fg"], activeforeground=t["bg"])

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=t["tree_bg"], foreground=t["tree_fg"], fieldbackground=t["tree_bg"],
                        rowheight=25)
        style.configure("Treeview.Heading", background=t["btn_primary"], foreground="white", font=("Arial", 10, "bold"))
        self.tree.tag_configure('evenrow', background=t["tree_row_even"], foreground=t["tree_fg"])
        self.tree.tag_configure('oddrow', background=t["tree_row_odd"], foreground=t["tree_fg"])

        self.btn_theme.config(bg=t["entry_bg"], fg=t["fg"])
        if self.tree.get_children(): self.refresh_table()

    # --- APP LOGIC ---
    def _on_tab_change(self, event):
        selected_tab = event.widget.select()
        tab_text = event.widget.tab(selected_tab, "text")
        if "Vault" in tab_text: self.refresh_table()

    def do_save(self):
        account = self.entry_account.get()
        raw_pass = self.entry_pass.get()
        if not account or not raw_pass:
            messagebox.showwarning("Error", "Fields cannot be empty")
            return
        encrypted_val = self.crypto.encrypt(raw_pass)
        success = self.db.save_entry(account, encrypted_val)
        if success:
            self.lbl_status_add.config(text=f"Saved: {account}", fg="#2ecc71")
            self.entry_pass.delete(0, tk.END)
            self.entry_account.delete(0, tk.END)
        else:
            self.lbl_status_add.config(text="Database Error", fg="red")

    def refresh_table(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        rows = self.db.fetch_all()
        for index, row in enumerate(rows):
            alias = row[0]
            enc_data = row[1]
            masked_data = enc_data[:10] + "..." + enc_data[-10:]
            tag = 'evenrow' if index % 2 == 0 else 'oddrow'
            self.tree.insert("", "end", iid=alias, values=(alias, masked_data), tags=(tag,))

    # --- POPUP LOGIC ---

    def _create_popup_window(self, title, height=200):
        t = THEMES[self.current_theme]
        popup = tk.Toplevel(self.root)
        popup.title(title)
        popup.geometry(f"400x{height}")
        popup.configure(bg=t["bg"])
        popup.transient(self.root)
        popup.grab_set()
        return popup, t

    def do_decrypt_popup(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Select a row first.")
            return
        alias = selected_item[0]
        full_encrypted_data = self.db.get_entry(alias)

        if full_encrypted_data:
            decrypted = self.crypto.decrypt(full_encrypted_data)
            if not decrypted:
                messagebox.showerror("Error", "Decryption failed! Wrong Master Password?")
                return

            popup, t = self._create_popup_window(f"Details: {alias}", height=280)

            tk.Label(popup, text="Account Name:", bg=t["bg"], fg="gray").pack(pady=(20, 0))
            tk.Label(popup, text=alias, font=("Arial", 12, "bold"), bg=t["bg"], fg=t["fg"]).pack()

            tk.Label(popup, text="Decrypted Password:", bg=t["bg"], fg="gray").pack(pady=(20, 0))
            lbl_pass_display = tk.Label(popup, text=decrypted, font=("Consolas", 14, "bold"),
                                        bg=t["bg"], fg="#3498db")
            lbl_pass_display.pack()

            def copy_to_clipboard():
                self.root.clipboard_clear()
                self.root.clipboard_append(decrypted)
                self.root.update()
                btn_copy.config(text="Copied!", bg="#8e44ad")

            btn_copy = tk.Button(popup, text="Copy to Clipboard", command=copy_to_clipboard,
                                 bg=t["btn_primary"], fg="white", font=("Arial", 10), width=20)
            btn_copy.pack(pady=20)

        else:
            messagebox.showerror("Error", "Data not found.")

    def do_edit_popup(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Select a row first.")
            return
        alias = selected_item[0]

        popup, t = self._create_popup_window(f"Edit Password: {alias}", height=250)

        tk.Label(popup, text=f"Update Password for '{alias}'", font=("Arial", 10, "bold"),
                 bg=t["bg"], fg=t["fg"]).pack(pady=20)

        entry_new_pass = tk.Entry(popup, width=30, show="*", font=("Consolas", 11), justify='center',
                                  bg=t["entry_bg"], fg=t["entry_fg"], insertbackground=t["fg"])
        entry_new_pass.pack(pady=10)
        entry_new_pass.focus()

        def save_changes():
            new_pass = entry_new_pass.get()
            if not new_pass:
                messagebox.showwarning("Error", "Password cannot be empty", parent=popup)
                return

            encrypted_val = self.crypto.encrypt(new_pass)
            success = self.db.save_entry(alias, encrypted_val)

            if success:
                messagebox.showinfo("Success", "Password Updated!", parent=popup)
                self.refresh_table()
                popup.destroy()

        btn_update = tk.Button(popup, text="Update Password", command=save_changes,
                               bg=t["btn_primary"], fg="white", font=("Arial", 10, "bold"), width=20)
        btn_update.pack(pady=20)


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()

    mp = simpledialog.askstring("Login", "Enter Master Password:", show='*')

    if mp:
        root.deiconify()
        app = MyCryptorApp(root, master_pass=mp)
        root.mainloop()
    else:
        root.destroy()