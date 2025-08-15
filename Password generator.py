import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import math
import string
import secrets
import time


SIMILAR_CHARS = set("lI1|!O0o")
AMBIGUOUS_SYMBOLS = set("{}[]()/\\'\"`~,;:.<>")

SYMBOLS_ALL = set("!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~")
SYMBOLS_SAFE = SYMBOLS_ALL - AMBIGUOUS_SYMBOLS

def build_charset(include_lower, include_upper, include_digits, include_symbols, avoid_similar, avoid_ambiguous):
    charset = set()
    if include_lower:
        charset.update(string.ascii_lowercase)
    if include_upper:
        charset.update(string.ascii_uppercase)
    if include_digits:
        charset.update(string.digits)
    if include_symbols:
        charset.update(SYMBOLS_SAFE if avoid_ambiguous else SYMBOLS_ALL)
    if avoid_similar:
        charset = {c for c in charset if c not in SIMILAR_CHARS}
    return "".join(sorted(charset))

def has_seq(s, span=3):
    
    if len(s) < span:
        return False
    for i in range(len(s) - span + 1):
        chunk = s[i:i+span]
    
        codes = [ord(c) for c in chunk]
        diffs = [codes[j+1]-codes[j] for j in range(len(codes)-1)]
        if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
            return True
    return False

def has_triple_repeat(s):
    if len(s) < 3:
        return False
    for i in range(len(s)-2):
        if s[i] == s[i+1] == s[i+2]:
            return True
    return False

def meets_category_requirements(pw, opts):
  
    if opts["lower"] and not any(c.islower() for c in pw):
        return False
    if opts["upper"] and not any(c.isupper() for c in pw):
        return False
    if opts["digits"] and not any(c.isdigit() for c in pw):
        return False
    if opts["symbols"]:
        allowed_syms = SYMBOLS_SAFE if opts["avoid_ambiguous"] else SYMBOLS_ALL
        if not any(c in allowed_syms for c in pw):
            return False
    return True

def forbidden_substrings_ok(pw, forbidden_list):
    for sub in forbidden_list:
        sub = sub.strip()
        if not sub:
            continue
        if sub.lower() in pw.lower():
            return False
    return True

def estimate_entropy_bits(length, charset_size):
   
    if charset_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(charset_size)

def generate_password(length, opts, forbidden_list, max_tries=5000):
    """
    Generate a password satisfying:
      - category requirements (if enforce_each=True)
      - no 3+ repeats
      - no 3-char ascending/descending sequences
      - forbids provided substrings (case-insensitive)
    """
    include_lower = opts["lower"]
    include_upper = opts["upper"]
    include_digits = opts["digits"]
    include_symbols = opts["symbols"]
    avoid_similar = opts["avoid_similar"]
    avoid_ambiguous = opts["avoid_ambiguous"]
    enforce_each = opts["enforce_each"]

    charset = build_charset(include_lower, include_upper, include_digits, include_symbols,
                            avoid_similar, avoid_ambiguous)

    if not charset:
        raise ValueError("No characters available. Enable at least one category.")


    categories = []
    if include_lower:
        categories.append(string.ascii_lowercase)
    if include_upper:
        categories.append(string.ascii_uppercase)
    if include_digits:
        categories.append(string.digits)
    if include_symbols:
        categories.append("".join(SYMBOLS_SAFE if avoid_ambiguous else SYMBOLS_ALL))

    for _ in range(max_tries):
        if enforce_each and categories:
            if length < len(categories):
                raise ValueError("Length too short for required categories.")
          
            pw_chars = [secrets.choice(cat) for cat in categories]
           
            pw_chars.extend(secrets.choice(charset) for _ in range(length - len(categories)))
            
            for i in range(len(pw_chars)-1, 0, -1):
                j = secrets.randbelow(i+1)
                pw_chars[i], pw_chars[j] = pw_chars[j], pw_chars[i]
            pw = "".join(pw_chars)
        else:
            pw = "".join(secrets.choice(charset) for _ in range(length))

        if has_triple_repeat(pw):
            continue
        if has_seq(pw, 3):
            continue
        if not forbidden_substrings_ok(pw, forbidden_list):
            continue
        if enforce_each and not meets_category_requirements(pw, opts):
            continue

        return pw

    raise RuntimeError("Could not generate a password satisfying all constraints. Relax options or increase length.")


class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Generator")
        self.root.geometry("860x560")
        self.root.minsize(820, 520)

        self.clipboard_clear_after_ms = 20000  

        self._build_ui()

    def _build_ui(self):
       
        opt = ttk.Frame(self.root, padding=12)
        opt.pack(fill="x")

        ttk.Label(opt, text="Length").grid(row=0, column=0, sticky="w")
        self.len_var = tk.IntVar(value=16)
        self.len_scale = ttk.Scale(opt, from_=8, to=128, orient="horizontal",
                                   command=self._on_length_change)
        self.len_scale.set(16)
        self.len_scale.grid(row=0, column=1, sticky="ew", padx=8)
        opt.columnconfigure(1, weight=1)

        self.len_label = ttk.Label(opt, text="16")
        self.len_label.grid(row=0, column=2, sticky="e")

       
        cat = ttk.LabelFrame(self.root, text="Character Sets & Rules", padding=12)
        cat.pack(fill="x", padx=12, pady=(0,12))

        self.lower_var = tk.BooleanVar(value=True)
        self.upper_var = tk.BooleanVar(value=True)
        self.digit_var = tk.BooleanVar(value=True)
        self.symbol_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(cat, text="Lowercase (a-z)", variable=self.lower_var).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(cat, text="Uppercase (A-Z)", variable=self.upper_var).grid(row=0, column=1, sticky="w")
        ttk.Checkbutton(cat, text="Digits (0-9)", variable=self.digit_var).grid(row=0, column=2, sticky="w")
        ttk.Checkbutton(cat, text="Symbols", variable=self.symbol_var).grid(row=0, column=3, sticky="w")

        self.similar_var = tk.BooleanVar(value=True)
        self.ambig_var = tk.BooleanVar(value=True)
        self.enforce_each_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(cat, text="Avoid similar (l I 1 | ! O 0 o)", variable=self.similar_var).grid(row=1, column=0, sticky="w", pady=(6,0))
        ttk.Checkbutton(cat, text="Avoid ambiguous symbols", variable=self.ambig_var).grid(row=1, column=1, sticky="w", pady=(6,0))
        ttk.Checkbutton(cat, text="Require one of each selected type", variable=self.enforce_each_var).grid(row=1, column=2, columnspan=2, sticky="w", pady=(6,0))

      
        forb = ttk.Frame(self.root, padding=(12,0,12,0))
        forb.pack(fill="x")
        ttk.Label(forb, text="Forbidden substrings (comma-separated, case-insensitive)").grid(row=0, column=0, sticky="w")
        self.forbidden_entry = ttk.Entry(forb)
        self.forbidden_entry.grid(row=1, column=0, sticky="ew", pady=6)
        forb.columnconfigure(0, weight=1)

      
        mid = ttk.Frame(self.root, padding=12)
        mid.pack(fill="x")

        ttk.Label(mid, text="Generated Password").grid(row=0, column=0, sticky="w")
        self.pw_var = tk.StringVar(value="")
        self.pw_entry = ttk.Entry(mid, textvariable=self.pw_var, show="•")
        self.pw_entry.grid(row=1, column=0, sticky="ew", padx=(0,8))
        mid.columnconfigure(0, weight=1)

        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(mid, text="Show", variable=self.show_var, command=self.toggle_show).grid(row=1, column=1, sticky="w")

        btns = ttk.Frame(mid)
        btns.grid(row=1, column=2, sticky="e")
        ttk.Button(btns, text="Generate", command=self.generate_one).grid(row=0, column=0, padx=4)
        ttk.Button(btns, text="Copy", command=self.copy_password).grid(row=0, column=1, padx=4)

        self.copy_status = ttk.Label(mid, text="")
        self.copy_status.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6,0))

       
        strength = ttk.Frame(self.root, padding=(12,0,12,0))
        strength.pack(fill="x", pady=(4,8))

        ttk.Label(strength, text="Strength").grid(row=0, column=0, sticky="w")
        self.str_bar = ttk.Progressbar(strength, mode="determinate", maximum=100)
        self.str_bar.grid(row=0, column=1, sticky="ew", padx=8)
        strength.columnconfigure(1, weight=1)
        self.str_label = ttk.Label(strength, text="Entropy: 0 bits  |  Very Weak")
        self.str_label.grid(row=0, column=2, sticky="e")

       
        bottom = ttk.Frame(self.root, padding=12)
        bottom.pack(fill="both", expand=True)

        left = ttk.Frame(bottom)
        left.pack(side="left", fill="y")
        ttk.Label(left, text="Generate").pack(anchor="w")
        gen_row = ttk.Frame(left)
        gen_row.pack(anchor="w", pady=(4,8))
        ttk.Label(gen_row, text="How many:").grid(row=0, column=0, padx=(0,6))
        self.count_var = tk.IntVar(value=5)
        ttk.Spinbox(gen_row, from_=1, to=1000, textvariable=self.count_var, width=8).grid(row=0, column=1)
        ttk.Button(left, text="Generate List", command=self.generate_many).pack(anchor="w", pady=6)
        ttk.Button(left, text="Save List…", command=self.save_list).pack(anchor="w")

        right = ttk.Frame(bottom)
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        ttk.Label(right, text="History / Generated List").pack(anchor="w")
        self.listbox = tk.Listbox(right, height=12)
        self.listbox.pack(fill="both", expand=True, pady=(4,0))
        ttk.Button(right, text="Copy Selected", command=self.copy_selected).pack(anchor="e", pady=8)

     
        s = ttk.Style()
        try:
            s.theme_use('clam')
        except:
            pass

    def _on_length_change(self, val):
        self.len_label.config(text=str(int(float(val))))

    def toggle_show(self):
        self.pw_entry.config(show="" if self.show_var.get() else "•")

    def _gather_options(self):
        return {
            "lower": self.lower_var.get(),
            "upper": self.upper_var.get(),
            "digits": self.digit_var.get(),
            "symbols": self.symbol_var.get(),
            "avoid_similar": self.similar_var.get(),
            "avoid_ambiguous": self.ambig_var.get(),
            "enforce_each": self.enforce_each_var.get(),
        }

    def _forbidden_list(self):
        raw = self.forbidden_entry.get().strip()
        if not raw:
            return []
        return [x.strip() for x in raw.split(",") if x.strip()]

    def _update_strength_meter(self, pw, opts):
        
        charset = build_charset(
            opts["lower"], opts["upper"], opts["digits"], opts["symbols"],
            opts["avoid_similar"], opts["avoid_ambiguous"]
        )
        bits = estimate_entropy_bits(len(pw), len(charset))
       
        if bits < 40:
            label = "Very Weak"
            pct = 10
        elif bits < 60:
            label = "Weak"
            pct = 30
        elif bits < 80:
            label = "Moderate"
            pct = 55
        elif bits < 100:
            label = "Strong"
            pct = 80
        else:
            label = "Very Strong"
            pct = 100

        
        if has_triple_repeat(pw) or has_seq(pw):
            pct = max(5, pct - 25)
            label += " (pattern penalty)"
        self.str_bar['value'] = pct
        self.str_label.config(text=f"Entropy: {int(bits)} bits  |  {label}")

    def generate_one(self):
        try:
            length = int(self.len_scale.get())
            opts = self._gather_options()
            if not any([opts["lower"], opts["upper"], opts["digits"], opts["symbols"]]):
                messagebox.showerror("Options Error", "Select at least one character category.")
                return
            pw = generate_password(length, opts, self._forbidden_list())
            self.pw_var.set(pw)
            self._update_strength_meter(pw, opts)
            self.listbox.insert(0, pw)
        except Exception as e:
            messagebox.showerror("Generation Error", str(e))

    def generate_many(self):
        try:
            count = max(1, int(self.count_var.get()))
            length = int(self.len_scale.get())
            opts = self._gather_options()
            if not any([opts["lower"], opts["upper"], opts["digits"], opts["symbols"]]):
                messagebox.showerror("Options Error", "Select at least one character category.")
                return
            generated = []
            for _ in range(count):
                pw = generate_password(length, opts, self._forbidden_list())
                generated.append(pw)
         
            for pw in reversed(generated):
                self.listbox.insert(0, pw)
           
            self.pw_var.set(generated[-1])
            self._update_strength_meter(generated[-1], opts)
        except Exception as e:
            messagebox.showerror("Generation Error", str(e))

    def copy_password(self):
        pw = self.pw_var.get()
        if not pw:
            return
        self._copy_to_clipboard(pw)

    def copy_selected(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        pw = self.listbox.get(sel[0])
        self._copy_to_clipboard(pw)

    def _copy_to_clipboard(self, text):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update_idletasks()
            self.copy_status.config(text="Copied to clipboard. Will auto-clear in 20s.")
            
            self.root.after(self.clipboard_clear_after_ms, self._clear_clipboard_if_same, text)
        except Exception as e:
            messagebox.showerror("Clipboard Error", str(e))

    def _clear_clipboard_if_same(self, text):
        try:
            current = self.root.clipboard_get()
            if current == text:
                self.root.clipboard_clear()
                self.copy_status.config(text="Clipboard cleared.")
        except:
            
            pass

    def save_list(self):
        if self.listbox.size() == 0:
            messagebox.showinfo("Nothing to Save", "No passwords in the list.")
            return
        path = filedialog.asksaveasfilename(
            title="Save Passwords",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for i in range(self.listbox.size()):
                    f.write(self.listbox.get(i) + "\n")
            messagebox.showinfo("Saved", f"Saved to {path}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

def main():
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
