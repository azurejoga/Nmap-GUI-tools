import wx
import subprocess
import threading
import os
import webbrowser

# Dicionário de descrições de parâmetros do Nmap
param_descriptions = {
    "TARGET SPECIFICATION": "Target specification",
    "-iL <inputfilename>": "Host/network list entry",
    "-iR <num hosts>": "Choose random targets",
    "--exclude <host1[ ,host2][,host3],...>": "Exclude hosts/networks",
    "--excludefile <exclude_file>": "Exclude file list",
    "HOST DISCOVERY": "Host discovery",
    "- sL": "Scan list - simply lists targets to scan",
    "-sP": "Ping scan - only determines if host is online",
    "-P0": "Treat all hosts as online - skip discovery hosts",
    "-PS/PA/PU <portlist>": "TCP SYN/ACK or UDP discovery probes for discovered ports",
    "- PE/PP/PM": "ICMP echo, timestamp and netmask request discovery probes ",
    "-n/-R": "Never do DNS resolution/Resolve always [default: resolve sometimes]",
    "--dns- servers <serv1[,serv2],...>": "Specify DNS servers custom",
    "--system-dns": "Use the operating system's DNS resolver",
    "SCAN TECHNIQUES": "Scanning techniques",
    "-sS/sT/sA/sW/sM": "TCP SYN/scans Connect()/ACK/Window/Maimon",
    "-sN/sF/sX": "TCP Null, FIN and Xmas scans",
    "--scanflags <flags>": "Customize TCP scan flags",
    "-sI <zombie host[:probeport]>": "Idlescan",
    "-sO": "IP protocol scan",
    "-b <ftp relay host>": "FTP hop scan",
    "PORT SPECIFICATION AND SCAN ORDER": "Port specification and scan order",
    "-p <port ranges>": "Scan only specified ports",
    "-F": "Fast - Scan only ports linked in the nmap-services file",
    "-r": "Scan ports sequentially - do not randomize",
    "SERVICE/VERSION DETECTION": "Service/version detection",
    "-sV": "Probe open ports to determine service/version information",
    "--version- intensity <level>": "Set from 0 (level) to 9 (try all probes)",
    "--version-light": "Limit to most likely probes (intensity 2)",
    "--version-all": "Try all probes (intensity 9)",
    "--version-trace": "Show detailed version scan activity (for debugging)",
    "OS DETECTION": "OS detection",
    "-O": "Enable OS detection (try 2nd generation, then 1st generation if that fails)",
    "-O1": "Use only the old OS detection system (1st generation)",
    "-O2": "Use only new OS detection system (no fallback)",
    "--osscan-limit": "Limit OS detection to promising targets",
    "--osscan-guess": "Guess OS accurately more aggressive",
    "TIMING AND PERFORMANCE": "Timing and performance",
    "-T[0-5]": "Set timing model (higher is faster)",
    "--min-hostgroup/max-hostgroup <size>": "Parallel hosts scan group size",
    "--min-parallelism/max-parallelism <numprobes>": "Probing parallelism",
    "--min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>": "Specific probe round-trip time.",
    "--max-retries <tries>": "Limit the number of port probe retransmissions",
    "--host-timeout <time>": "Give up target after this time",
    "--scan-delay/--max-scan-delay <time>": "Adjust the delay between probes",
    "FIREWALL/IDS EVASION AND SPOOFING": "Firewall/IDS evasion and spoofing",
    "-f; --mtu <val>": "Fragment packets (optionally with provided MTU)",
    "-D <decoy1,decoy2[,ME],...>": "Disguise a scan with decoys",
    "-S <IP_Address>": "Fake source address",
    "-e <iface>": "Use specified interface",
    "-g/--source-port <portnum>": "Use given port number",
    "--data-length <num>": "Append random data to sent packets",
    "--ttl <val>": "Set IP lifetime field",
    "--spoof-mac <mac address, prefix, or vendor name>": "Fake your MAC address",
    "OUTPUT": "Output",
    "-oN/-oX/-oS/-oG <file>": "Output scan results in normal format, XML, s| <rIpt kIddi3 and Grepable respectively for the given file",
    "-oA <basename>": "Output in three principles" 
}

perfis = {
    "Fast": "-T4",
    "Intensive": "-T5",
    "Intense": "-T3",
    "Full": "-T5 -A -v"
}

class PortScannerApp(wx.Frame):
    def __init__(self):
        super().__init__(None, title="Nmap, GUI interface: by azurejoga", size=(500, 400))
        panel = wx.Panel(self)
        self.target_label = wx.StaticText(panel, label="Target:")
        self.target_text = wx.TextCtrl(panel)
        self.param_label = wx.StaticText(panel, label="Nmap parameters:")
        self.param_combobox = wx.ComboBox(panel, choices=list(param_descriptions.keys()), style=wx.CB_DROPDOWN)
        self.param_combobox.SetValue("--help")  # Parâmetro inicial
        self.param_description_label = wx.StaticText(panel, label="", style=wx.ALIGN_LEFT | wx.ST_NO_AUTORESIZE)
        self.scan_button = wx.Button(panel, label="Start Scan")
        self.cancel_button = wx.Button(panel, label="Cancel Scan")
        self.cancel_button.Disable()

        self.profile_label = wx.StaticText(panel, label="Scan Profile:")
        self.profile_combobox = wx.ComboBox(panel, choices=list(perfis.keys()), style=wx.CB_READONLY)
        self.result_label = wx.StaticText(panel, label="Scan Results:")
        self.result_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY, name="Scan Results")
        
        self.save_button = wx.Button(panel, label="Save Results")
        self.save_button.Disable()

        self.scan_button.Bind(wx.EVT_BUTTON, self.start_scan)
        self.cancel_button.Bind(wx.EVT_BUTTON, self.cancel_scan)
        self.param_combobox.Bind(wx.EVT_COMBOBOX, self.update_param_description)
        self.save_button.Bind(wx.EVT_BUTTON, self.save_results)

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.target_label, 0, wx.ALL, 5)
        sizer.Add(self.target_text, 0, wx.EXPAND | wx.ALL, 5)
        sizer.Add(self.param_label, 0, wx.ALL, 5)
        sizer.Add(self.param_combobox, 0, wx.EXPAND | wx.ALL, 5)
        sizer.Add(self.param_description_label, 0, wx.EXPAND | wx.ALL, 5)
        sizer.Add(self.profile_label, 0, wx.ALL, 5)
        sizer.Add(self.profile_combobox, 0, wx.EXPAND | wx.ALL, 5)
        sizer.Add(self.scan_button, 0, wx.EXPAND | wx.ALL, 5)
        sizer.Add(self.cancel_button, 0, wx.EXPAND | wx.ALL, 5)
        sizer.Add(self.result_label, 0, wx.ALL, 5)
        sizer.Add(self.result_text, 1, wx.EXPAND | wx.ALL, 5)
        sizer.Add(self.save_button, 0, wx.EXPAND | wx.ALL, 5)

        panel.SetSizer(sizer)
        self.Centre()
        self.Show()

        # Verificar se o Nmap está instalado no sistema ao iniciar o programa
        nmap_installed = self.check_nmap_installed()
        if not nmap_installed:
            self.install_nmap_dialog()

    def check_nmap_installed(self):
        try:
            subprocess.check_output(["nmap", "--version"])
            return True
        except FileNotFoundError:
            return False

    def install_nmap_dialog(self):
        dlg = wx.MessageDialog(self, "Nmap não está instalado no sistema. Deseja instalar o Nmap agora?",
                               "Nmap não encontrado", wx.YES_NO | wx.ICON_QUESTION)
        result = dlg.ShowModal()
        dlg.Destroy()

        if result == wx.ID_YES:
            webbrowser.open("https://nmap.org/download#windows")

    def update_param_description(self, event):
        selected_param = self.param_combobox.GetValue()
        description = param_descriptions.get(selected_param, "No description available")
        self.param_description_label.SetLabel(description)

    def start_scan(self, event):
        self.cancel_button.Enable()
        self.scan_button.Disable()
        self.save_button.Disable()
        target = self.target_text.GetValue()
        profile = self.profile_combobox.GetValue()
        params = perfis.get(profile, "") + " " + self.param_combobox.GetValue()
        command = f"nmap {params} {target}"

        # Verificar se o Nmap está instalado no sistema
        try:
            subprocess.check_output(["nmap", "--version"])
        except FileNotFoundError:
            dlg = wx.MessageDialog(self, "Nmap não está instalado no sistema. Deseja instalar o Nmap agora?",
                                   "Nmap não encontrado", wx.YES_NO | wx.ICON_QUESTION)
            result = dlg.ShowModal()
            dlg.Destroy()

            if result == wx.ID_YES:
                webbrowser.open("https://nmap.org/download#windows")

            self.cancel_button.Disable()
            self.scan_button.Enable()
            return

        def run_scan():
            self.result_text.SetValue("Running the following command:\n" + command + "\n\n")
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while process.poll() is None:
                output = process.stdout.readline().decode("utf-8")
                wx.CallAfter(self.result_text.AppendText, output)
            self.scan_button.Enable()
            self.cancel_button.Disable()
            self.save_button.Enable()

        self.scan_thread = threading.Thread(target=run_scan)
        self.scan_thread.start()

    def cancel_scan(self, event):
        self.scan_thread.join()
        self.cancel_button.Disable()
        self.scan_button.Enable()
        self.result_text.AppendText("\n\n--- Escaneamento cancelado ---\n")

    def save_results(self, event):
        dialog = wx.FileDialog(self, message="Save scan results", defaultDir=os.getcwd(),
                              defaultFile="resultes.txt", wildcard="Arquivos de Texto (*.txt)|*.txt",
                              style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT)
        if dialog.ShowModal() == wx.ID_OK:
            file_path = dialog.GetPath()
            with open(file_path, "w") as file:
                file.write(self.result_text.GetValue())
            wx.MessageBox("Results saved successfully!", "Save Completed", wx.OK | wx.ICON_INFORMATION)

app = wx.App()
frame = PortScannerApp()
frame.Show()
app.MainLoop()
