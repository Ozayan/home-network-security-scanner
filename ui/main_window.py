import csv
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from scanner.discovery import detect_local_network, scan_network, validate_private_network


class NetworkScannerApp:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.root = ctk.CTk()
        self.root.title("Home Network Security Scanner")
        self.root.geometry("980x640")
        self.root.minsize(820, 520)
        self.results = []
        self.stop_event = threading.Event()
        self._build()

    def _build(self):
        header = ctk.CTkFrame(self.root, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(22, 12))
        ctk.CTkLabel(header, text="Home Network Security Scanner", font=("Segoe UI", 25, "bold")).pack(anchor="w")
        ctk.CTkLabel(header, text="Inventário educacional de serviços TCP em redes privadas autorizadas.", text_color="gray70").pack(anchor="w", pady=(3, 0))

        controls = ctk.CTkFrame(self.root)
        controls.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(controls, text="Rede (CIDR)").pack(side="left", padx=(16, 8), pady=16)
        self.network_entry = ctk.CTkEntry(controls, width=220)
        self.network_entry.insert(0, detect_local_network())
        self.network_entry.pack(side="left", padx=5)
        self.scan_button = ctk.CTkButton(controls, text="Iniciar scan", command=self.start_scan)
        self.scan_button.pack(side="left", padx=10)
        self.stop_button = ctk.CTkButton(controls, text="Parar", width=85, fg_color="#8b2535", state="disabled", command=self.stop_scan)
        self.stop_button.pack(side="left")
        self.progress = ctk.CTkProgressBar(controls, width=180)
        self.progress.set(0)
        self.progress.pack(side="right", padx=16)

        self.summary = ctk.CTkLabel(self.root, text="Pronto para verificar a rede.", anchor="w")
        self.summary.pack(fill="x", padx=28, pady=(8, 4))

        table_frame = ctk.CTkFrame(self.root)
        table_frame.pack(fill="both", expand=True, padx=24, pady=8)
        columns = ("ip", "hostname", "ports", "services", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        widths = (120, 210, 140, 270, 100)
        headings = ("IP", "Hostname", "Portas abertas", "Serviços", "Status")
        for col, heading, width in zip(columns, headings, widths):
            self.tree.heading(col, text=heading)
            self.tree.column(col, width=width, minwidth=70)
        self.tree.tag_configure("OK", foreground="#36b37e")
        self.tree.tag_configure("Atenção", foreground="#f5a623")
        self.tree.tag_configure("Revisar", foreground="#ff5c5c")
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scroll.pack(side="right", fill="y", padx=(0, 10), pady=10)

        footer = ctk.CTkFrame(self.root, fg_color="transparent")
        footer.pack(fill="x", padx=24, pady=(4, 18))
        self.csv_button = ctk.CTkButton(footer, text="Exportar CSV", state="disabled", command=self.export_csv)
        self.csv_button.pack(side="left", padx=(0, 8))
        self.json_button = ctk.CTkButton(footer, text="Exportar JSON", state="disabled", command=self.export_json)
        self.json_button.pack(side="left")
        self.about_button = ctk.CTkButton(footer, text="About", width=85, fg_color="#3a3a3a", command=self.show_about)
        self.about_button.pack(side="right")
        ctk.CTkLabel(footer, text="Use apenas em redes próprias ou com autorização.", text_color="gray60").pack(side="right")

    def start_scan(self):
        try:
            validate_private_network(self.network_entry.get())
        except ValueError as exc:
            messagebox.showerror("Rede inválida", str(exc))
            return
        self.results = []
        self.stop_event.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.csv_button.configure(state="disabled")
        self.json_button.configure(state="disabled")
        self.summary.configure(text="Verificando dispositivos e portas comuns...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            results = scan_network(self.network_entry.get(), self._queue_progress, self.stop_event)
            self.root.after(0, self._finish_scan, results, None)
        except Exception as exc:
            self.root.after(0, self._finish_scan, [], str(exc))

    def _queue_progress(self, done, total, result):
        self.root.after(0, self._update_progress, done, total, result)

    def _update_progress(self, done, total, result):
        self.progress.set(done / total if total else 0)
        self.summary.configure(text=f"Verificados {done}/{total} endereços — {len(self.tree.get_children())} dispositivo(s) encontrado(s).")
        if result:
            self.tree.insert("", "end", values=(result["ip"], result["hostname"], ", ".join(map(str, result["open_ports"])), ", ".join(result["services"]), result["status"]), tags=(result["status"],))

    def _finish_scan(self, results, error):
        self.results = results
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        if error:
            self.summary.configure(text="O scan não pôde ser concluído.")
            messagebox.showerror("Erro", error)
            return
        stopped = self.stop_event.is_set()
        self.summary.configure(text=f"{'Scan interrompido' if stopped else 'Scan concluído'}: {len(results)} dispositivo(s) com portas monitoradas abertas.")
        state = "normal" if results else "disabled"
        self.csv_button.configure(state=state)
        self.json_button.configure(state=state)

    def stop_scan(self):
        self.stop_event.set()
        self.summary.configure(text="Interrompendo o scan...")

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with Path(path).open("w", newline="", encoding="utf-8-sig") as output:
            writer = csv.DictWriter(output, fieldnames=["ip", "hostname", "open_ports", "services", "status", "findings"])
            writer.writeheader()
            for item in self.results:
                writer.writerow({**item, "open_ports": ";".join(map(str, item["open_ports"])), "services": ";".join(item["services"]), "findings": ";".join(item["findings"])})
        messagebox.showinfo("Exportação", "Relatório CSV salvo com sucesso.")

    def export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        payload = {"generated_at": datetime.now(timezone.utc).isoformat(), "network": self.network_entry.get(), "devices": self.results}
        Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        messagebox.showinfo("Exportação", "Relatório JSON salvo com sucesso.")

    def show_about(self):
        messagebox.showinfo("About", "Desenvolvido por Zayan Teixeira Correa")

    def run(self):
        self.root.mainloop()
