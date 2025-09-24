# pm_app_gui.py
#!/usr/bin/env python3
import sys, os, threading, io, traceback
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

# Ensure we can import mini_pm next to this file
APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

try:
    import mini_pm  # must have run_all(input_path, map_csv, target_version, report_root, alert_days)
except Exception as e:
    messagebox.showerror("Import error", f"Could not import mini_pm.py:\n{e}")
    raise

class TeeWriter:
    """Mirror writes to original stream and Tk text widget (via thread-safe .after)."""
    def __init__(self, text_widget: ScrolledText, original):
        self.text = text_widget
        self.original = original

    def write(self, data):
        # write to original
        try:
            self.original.write(data)
        except Exception:
            pass
        # write to GUI (on main thread)
        if data:
            self.text.after(0, self._append, data)

    def flush(self):
        try:
            self.original.flush()
        except Exception:
            pass

    def _append(self, data):
        self.text.insert(tk.END, data)
        self.text.see(tk.END)

class PMApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PM App (GUI)")
        self.geometry("900x600")
        self.resizable(True, True)

        # Inputs
        row = 0
        tk.Label(self, text="Input (ZIP or folder):").grid(row=row, column=0, sticky="e", padx=6, pady=6)
        self.inp_var = tk.StringVar()
        tk.Entry(self, textvariable=self.inp_var, width=70).grid(row=row, column=1, sticky="we", padx=6, pady=6)
        tk.Button(self, text="Browse…", command=self.browse_input).grid(row=row, column=2, padx=6, pady=6)

        row += 1
        tk.Label(self, text="Mapping CSV (ora_code_table.csv):").grid(row=row, column=0, sticky="e", padx=6, pady=6)
        self.map_var = tk.StringVar()
        tk.Entry(self, textvariable=self.map_var, width=70).grid(row=row, column=1, sticky="we", padx=6, pady=6)
        tk.Button(self, text="Browse…", command=self.browse_map).grid(row=row, column=2, padx=6, pady=6)

        row += 1
        tk.Label(self, text="Target version (RU):").grid(row=row, column=0, sticky="e", padx=6, pady=6)
        self.ver_var = tk.StringVar(value="19.27")
        tk.Entry(self, textvariable=self.ver_var, width=15).grid(row=row, column=1, sticky="w", padx=6, pady=6)

        tk.Label(self, text="Alert days (last N days):").grid(row=row, column=1, sticky="e", padx=6, pady=6)
        self.days_var = tk.StringVar(value="92")
        tk.Entry(self, textvariable=self.days_var, width=8).grid(row=row, column=1, sticky="w", padx=(170,6), pady=6)

        row += 1
        tk.Label(self, text="Output root folder:").grid(row=row, column=0, sticky="e", padx=6, pady=6)
        default_out = str(Path.cwd() / "mini_pm_report")
        self.out_var = tk.StringVar(value=default_out)
        tk.Entry(self, textvariable=self.out_var, width=70).grid(row=row, column=1, sticky="we", padx=6, pady=6)
        tk.Button(self, text="Browse…", command=self.browse_out).grid(row=row, column=2, padx=6, pady=6)

        # Buttons
        row += 1
        self.run_btn = tk.Button(self, text="Run", command=self.run_clicked, width=12)
        self.run_btn.grid(row=row, column=1, sticky="w", padx=6, pady=6)

        self.open_btn = tk.Button(self, text="Open Output Folder", command=self.open_out, width=18, state=tk.DISABLED)
        self.open_btn.grid(row=row, column=1, sticky="e", padx=6, pady=6)

        # Console
        row += 1
        tk.Label(self, text="Console output:").grid(row=row, column=0, sticky="ne", padx=6, pady=6)
        self.console = ScrolledText(self, wrap=tk.WORD, height=25)
        self.console.grid(row=row, column=1, columnspan=2, sticky="nsew", padx=6, pady=6)

        # Grid weights
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(row, weight=1)

        self._last_out_dir = None
        self._runner_thread = None

    def browse_input(self):
        # allow file or folder
        f = filedialog.askopenfilename(title="Choose ZIP or any file inside the folder")
        if f:
            self.inp_var.set(f)
        else:
            # maybe choose a directory instead
            d = filedialog.askdirectory(title="Choose extracted folder")
            if d:
                self.inp_var.set(d)

    def browse_map(self):
        f = filedialog.askopenfilename(title="Choose ora_code_table.csv", filetypes=[("CSV files","*.csv"),("All files","*.*")])
        if f:
            self.map_var.set(f)

    def browse_out(self):
        d = filedialog.askdirectory(title="Choose output folder")
        if d:
            self.out_var.set(d)

    def open_out(self):
        path = Path(self.out_var.get())
        try:
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception as e:
            messagebox.showerror("Open folder", f"Could not open folder:\n{e}")

    def run_clicked(self):
        # Validate
        input_path = Path(self.inp_var.get().strip('"'))
        if not input_path.exists():
            messagebox.showerror("Input", "Input ZIP/folder does not exist.")
            return

        map_csv = self.map_var.get().strip()
        if map_csv and not Path(map_csv).exists():
            if not messagebox.askyesno("Mapping CSV", "Mapping CSV not found. Continue without cause/action mapping?"):
                return
            map_csv = ""

        try:
            alert_days = int(self.days_var.get())
            if alert_days <= 0:
                raise ValueError
        except Exception:
            messagebox.showerror("Alert days", "Please enter a positive integer for 'Alert days'.")
            return

        target_ver = self.ver_var.get().strip() or "19.27"
        out_root = Path(self.out_var.get().strip() or (Path.cwd() / "mini_pm_report"))
        out_root.mkdir(parents=True, exist_ok=True)
        self._last_out_dir = out_root

        # Clear console and run
        self.console.delete("1.0", tk.END)
        self.run_btn.config(state=tk.DISABLED)
        self.open_btn.config(state=tk.DISABLED)

        def worker():
            # Capture stdout/stderr
            orig_out, orig_err = sys.stdout, sys.stderr
            tee = TeeWriter(self.console, orig_out)
            sys.stdout = tee
            sys.stderr = tee
            try:
                mini_pm.run_all(
                    input_path=input_path,
                    map_csv=Path(map_csv) if map_csv else None,
                    target_version=target_ver,
                    report_root=out_root,
                    alert_days=alert_days,
                )
                self.console.after(0, lambda: self.open_btn.config(state=tk.NORMAL))
            except Exception:
                err = traceback.format_exc()
                self.console.after(0, lambda: self.console.insert(tk.END, "\n" + err + "\n"))
                messagebox.showerror("Error", "An error occurred. See console output.")
            finally:
                sys.stdout = orig_out
                sys.stderr = orig_err
                self.run_btn.config(state=tk.NORMAL)

        self._runner_thread = threading.Thread(target=worker, daemon=True)
        self._runner_thread.start()

if __name__ == "__main__":
    app = PMApp()
    app.mainloop()
