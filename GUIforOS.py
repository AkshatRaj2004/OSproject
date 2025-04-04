import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import psutil
import threading
import concurrent.futures
from system_monitor import get_system_processes
from deadlock_detection import detect_resource_contention
from deadlock_prevention import is_safe_state

class SystemMonitorApp:
    def _init_(self, root):
        self.root = root
        self.root.title("🖥 System Monitor & Deadlock Manager")
        self.root.geometry("900x600")
        self.root.configure(bg="#121212")

        # Apply ttk theme for a modern look
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TLabel", foreground="#00FF00", background="#121212", font=("Courier", 14, "bold"))
        self.style.configure("TButton", font=("Arial", 10, "bold"), background="#1E1E1E", foreground="white", padding=10)
        self.style.map("TButton", background=[("active", "#282828")])

        # Main Frame
        self.main_frame = ttk.Frame(root, padding=20, style="TFrame")
        self.main_frame.pack(expand=True, fill=tk.BOTH)

        # Title Label
        self.title_label = ttk.Label(self.main_frame, text="🟢 SYSTEM MONITOR & DEADLOCK MANAGER", style="TLabel")
        self.title_label.pack(pady=10)

        # Output Area
        self.output_area = scrolledtext.ScrolledText(
            self.main_frame, wrap=tk.WORD, width=100, height=15,
            font=("Consolas", 10), background="#1E1E1E", foreground="#00FF00",
            insertbackground="white", borderwidth=2, relief=tk.FLAT
        )
        self.output_area.pack(pady=10, fill=tk.BOTH, expand=True)

        # Buttons Frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(pady=10)

        # Buttons
        buttons = [
            ("📊 Monitor System", self.monitor_system),
            ("🔍 Detect Deadlocks", self.detect_deadlocks),

            ("🛑 Resolve Deadlock", self.resolve_deadlock),
        ]
        for text, command in buttons:
            btn = ttk.Button(self.button_frame, text=text, command=command, cursor="hand2")
            btn.pack(side=tk.LEFT, padx=10)

        # Status Bar
        self.status_var = tk.StringVar(value="Status: Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, anchor=tk.W, font=("Arial", 10),
                                    background="#1E1E1E", foreground="white", padding=5)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def update_status(self, message):
        """Update the status bar"""
        self.status_var.set(f"Status: {message}")

    def monitor_system(self):
        """Fetch and display system processes along with CPU & RAM usage"""
        def run_monitor():
            self.update_status("Fetching system stats...")
            self.output_area.delete(1.0, tk.END)
            self.output_area.insert(tk.END, "\n📊 Fetching system stats...\n")

            cpu_usage = psutil.cpu_percent(interval=1)
            ram_usage = psutil.virtual_memory().percent
            self.output_area.insert(tk.END, f"💻 CPU Usage: {cpu_usage}%\n")
            self.output_area.insert(tk.END, f"📌 RAM Usage: {ram_usage}%\n\n")

            processes = get_system_processes()
            for proc in processes:
                self.output_area.insert(tk.END, f"🔹 {proc}\n")
            self.update_status("Monitoring completed")

        threading.Thread(target=run_monitor, daemon=True).start()

    def detect_deadlocks(self):
        """Detect and display deadlocks"""
        def run_detection():
            self.update_status("Checking for deadlocks...")
            self.output_area.delete(1.0, tk.END)
            self.output_area.insert(tk.END, "\n🔍 Checking for Deadlocks...\n")
            deadlocks = detect_resource_contention()
            if not deadlocks:
                self.output_area.insert(tk.END, "✅ No deadlocks detected.\n")
            else:
                self.output_area.insert(tk.END, "⚠ Deadlocks detected!\n")
                for resource, pids in deadlocks.items():
                    self.output_area.insert(tk.END, f"🔴 Resource {resource} held by: {', '.join(map(str, pids))}\n")
            self.update_status("Deadlock check completed")

        threading.Thread(target=run_detection, daemon=True).start()
    def resolve_deadlock(self):
        """Resolve deadlocks by terminating the lowest priority process"""
        self.update_status("Attempting to resolve deadlocks...")
        deadlocks = detect_resource_contention()
        if not deadlocks:
            messagebox.showinfo("No Deadlocks", "No deadlocks detected.")
            self.update_status("No deadlocks found")
            return

        for resource, pids in deadlocks.items():
            try:
                lowest_priority_pid = min(pids, key=lambda pid: psutil.Process(pid).nice())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            confirm = messagebox.askyesno("Resolve Deadlock", f"Terminate process {lowest_priority_pid} to resolve deadlock?")
            if confirm:
                try:
                    psutil.Process(lowest_priority_pid).terminate()
                    self.output_area.insert(tk.END, f"🛑 Process {lowest_priority_pid} terminated to resolve deadlock.\n")
                    messagebox.showinfo("Deadlock Resolved", f"Process {lowest_priority_pid} was terminated.")
                    self.update_status("Deadlock resolved")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not terminate process {lowest_priority_pid}: {e}")
                    self.update_status("Error resolving deadlock")
                return

if _name_ == "_main_":
    root = tk.Tk()
    app = SystemMonitorApp(root)
    root.mainloop()
