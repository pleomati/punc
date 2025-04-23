import psutil
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import requests
import socket
import speedtest
from PIL import Image, ImageTk
import sys, os
import json
import pyuac


refreshing = True
seen_processes = set()
whitelist = set()
blacklist = set()
selected_pid = None
blocked_apps = set()  # Zbiór do przechowywania zablokowanych aplikacji

# Sprawdzenie, czy program jest uruchamiany z prawami administratora
def check_admin():
    if not pyuac.isUserAdmin():
        messagebox.showinfo("Administrator Rights Required", "This application needs to be run as an administrator.")
        sys.exit()  # Zakończenie bieżącego procesu
    
# Funkcja do geolokalizacji na podstawie adresu IP
def geolocate_ip(ip_address):
    try:
        response = requests.get(f'https://ipinfo.io/{ip_address}/json')
        data = response.json()
        location_info = f"""
        Adres IP: {data.get('ip', 'N/A')}
        Kraj: {data.get('country', 'N/A')}
        Stan: {data.get('region', 'N/A')}
        Miasto: {data.get('city', 'N/A')}
        Organization: {data.get('org', 'N/A')}
        """
        return location_info.strip()
    except Exception as e:
        return f"An error occurred while fetching location data: {e}"

# Funkcja do wyszukiwania adresu IP na podstawie domeny
def lookup_ip():
    domain = domain_entry.get()
    if not domain:
        messagebox.showwarning("Warning", "Proszę wprowadzić nazwę domeny.")
        return
    try:
        ip_address = socket.gethostbyname(domain)
        ip_result_label.config(text=f"Adres IP: {ip_address}")
        location_info = geolocate_ip(ip_address)
        messagebox.showinfo("Geolocation Info", location_info)
    except socket.error as e:
        messagebox.showerror("Error", f"Wystąpił błąd przy wyszukiwaniu adresu IP:\n{e}")

# Funkcja do przekierowywania portów
def redirect_port():
    source_ip = ip1_combobox.get()
    source_port = port1_combobox.get()
    destination_ip = ip2_combobox.get()
    destination_port = port2_combobox.get()

    if not all([source_ip, source_port, destination_ip, destination_port]):
        messagebox.showwarning("Incomplete Data", "Please fill out all fields.")
        return

    if not (source_port.isdigit() and destination_port.isdigit()):
        messagebox.showwarning("Invalid Port", "Ports must be numeric.")
        return

    protocol = protocol_var.get()  # Pobieranie wybranego protokołu
    redirect_cmd = f'netsh interface portproxy add v4tov4 listenaddress={source_ip} listenport={source_port} connectaddress={destination_ip} connectport={destination_port} protocol={protocol}'

    try:
        subprocess.run(redirect_cmd, shell=True, check=True)
        messagebox.showinfo("Success", f"Port {source_port} on {source_ip} has been redirected to {destination_port} on {destination_ip}.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"An error occurred while redirecting the port:\n{e}")


# Funkcja do otwierania portu
def open_port(port):
    protocol = protocol_var.get()  # Pobieranie wybranego protokołu
    
    # Najpierw sprawdź, czy reguła "Block port" istnieje
    #check1_cmd = f'netsh advfirewall firewall show rule name="Block port {port}" protocol={protocol} dir=in'
    check1_cmd = f'netsh advfirewall firewall show rule name="PUNC Block port {port}" dir=in'
    try:
        subprocess.run(check1_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Reguła istnieje, usuń ją
        #open_cmd1 = f'netsh advfirewall firewall delete rule name="Block port {port}" protocol={protocol} dir=in'
        open_cmd1 = f'netsh advfirewall firewall delete rule name="PUNC Block port {port}" dir=in'
        subprocess.run(open_cmd1, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        # Reguła nie istnieje, przejdź do dodania nowej reguły
        pass

    # Następnie dodaj nową regułę, która blokuje port
    open_cmd2 = f'netsh advfirewall firewall add rule name="PUNC Allow port {port}" protocol={protocol} dir=in localport={port} action=allow'
    subprocess.run(open_cmd2, shell=True, check=True)

    messagebox.showinfo("Success", f"Port {port} has been opened with {protocol}.")

def close_port(port):
    protocol = protocol_var.get()  # Pobieranie wybranego protokołu
    try:
        # Najpierw sprawdź, czy reguła "Allow port" istnieje
        #check_cmd = f'netsh advfirewall firewall show rule name="Allow port {port}" protocol={protocol} dir=in'
        check_cmd = f'netsh advfirewall firewall show rule name="PUNC Allow port {port}" dir=in'
        try:
            subprocess.run(check_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Reguła istnieje, usuń ją
            #close_cmd1 = f'netsh advfirewall firewall delete rule name="Allow port {port}" protocol={protocol} dir=in'
            close_cmd1 = f'netsh advfirewall firewall delete rule name="PUNC Allow port {port}" dir=in'
            subprocess.run(close_cmd1, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            # Reguła nie istnieje, przejdź do dodania nowej reguły
            pass

        # Następnie dodaj nową regułę, która blokuje port
        close_cmd2 = f'netsh advfirewall firewall add rule name="PUNC Block port {port}" protocol={protocol} dir=in localport={port} action=block'
        subprocess.run(close_cmd2, shell=True, check=True)

        messagebox.showinfo("Success", f"Port {port} has been closed with {protocol}.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"An error occurred while closing the port: {e}")


# Funkcje do obsługi przycisków w zakładce Ports
def on_open_port():
    port = port_entry.get()
    if port.isdigit() and 0 < int(port) < 65536:
        open_port(int(port))
    else:
        messagebox.showwarning("Invalid Port", "Please enter a valid port number (1-65535).")

def on_close_port():
    port = port_entry.get()
    if port.isdigit() and 0 < int(port) < 65536:
        close_port(int(port))
    else:
        messagebox.showwarning("Invalid Port", "Please enter a valid port number (1-65535).")

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
    

def on_allow_blocked_process():
    selected_item = blocked_apps_tree.focus()
    if not selected_item:
        messagebox.showwarning("No selection", "Please select a blocked process that you want to unblock.")
        return
    selected_app = blocked_apps_tree.item(selected_item)['values'][0]
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == selected_app:
            allow_internet(proc.pid)
            blocked_apps.remove(selected_app)  # Usuń z listy zablokowanych aplikacji
            update_blocked_apps_file(selected_app)  # Aktualizuj plik zablokowanych aplikacji
            update_blocked_apps_list()  # Zaktualizuj listę wyświetlaną w GUI
            return
    messagebox.showwarning("Process not found", f"The process {selected_app} is not running.")

def update_blocked_apps_file(allowed_app):
    blocked_apps_file = "blocked_app_list"  # Podaj właściwą ścieżkę do pliku
    try:
        # Wczytaj wszystkie zablokowane aplikacje
        with open(blocked_apps_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        # Zapisz z powrotem tylko te, które nie są odblokowywane
        with open(blocked_apps_file, 'w', encoding='utf-8') as file:
            for line in lines:
                if line.strip() != allowed_app:  # Zapisz te, które są inne
                    file.write(line)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while updating the blocked apps file:\n{e}")
    
def allow_internet(pid):
    try:
        process = psutil.Process(pid)
        program_path = process.exe()
        
        # Usuwamy reguły blokujące w zaporze
        allow_out_cmd = f'netsh advfirewall firewall delete rule name="Zablokuj {process.name()}" dir=out program="{program_path}"'
        allow_in_cmd = f'netsh advfirewall firewall delete rule name="Zablokuj {process.name()}" dir=in program="{program_path}"'

        subprocess.run(allow_out_cmd, shell=True, check=True)
        subprocess.run(allow_in_cmd, shell=True, check=True)

        messagebox.showinfo("Success", f"Internet access for the process {process.name()} (PID: {pid}) has been allowed.")
    except psutil.NoSuchProcess:
        messagebox.showerror("Error", f"The process with PID {pid} does not exist.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"An error occurred while allowing internet access:\n{e}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred:\n{e}")

def on_allow_internet():
    selected_item = process_tree.focus()
    if not selected_item:
        messagebox.showwarning("No selection", "Please select a process that you want to allow.")
        return
    pid = process_tree.item(selected_item)['values'][0]
    allow_internet(pid)

def block_internet(pid):
    try:
        process = psutil.Process(pid)
        program_path = process.exe()

        block_out_cmd = f'netsh advfirewall firewall add rule name="Zablokuj {process.name()}" dir=out action=block program="{program_path}"'
        block_in_cmd = f'netsh advfirewall firewall add rule name="Zablokuj {process.name()}" dir=in action=block program="{program_path}"'

        subprocess.run(block_out_cmd, shell=True, check=True)
        subprocess.run(block_in_cmd, shell=True, check=True)
        
        # Zapisz nazwę procesu do pliku
        with open('blocked_app_list', 'a') as file:
            file.write(f"{process.name()}\n")
        
        blocked_apps.add(process.name())
        messagebox.showinfo("Success", f"Internet access for the process {process.name()} (PID: {pid}) has been blocked.")
    except psutil.NoSuchProcess:
        messagebox.showerror("Error", f"The process with PID {pid} does not exist.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"An error occurred while blocking internet access:\n{e}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred:\n{e}")

def on_block_internet():
    selected_item = process_tree.focus()
    if not selected_item:
        messagebox.showwarning("No selection", "Please select a process that you want to block.")
        return
    pid = process_tree.item(selected_item)['values'][0]
    block_internet(pid)

def load_whitelist():
    try:
        with open('whitelist.txt', 'r') as file:
            for line in file:
                whitelist.add(line.strip())
    except FileNotFoundError:
        messagebox.showwarning("File not found", "The whitelist.txt file was not found. Processes will not be checked.")

def load_blacklist():
    try:
        with open('blacklist.txt', 'r') as file:
            for line in file:
                blacklist.add(line.strip())
    except FileNotFoundError:
        messagebox.showwarning("File not found", "The blacklist.txt file was not found. Processes will not be checked.")

def add_to_whitelist(name):
    if name not in whitelist:
        whitelist.add(name)
        with open('whitelist.txt', 'a') as file:
            file.write(f"{name}\n")
        messagebox.showinfo("Success", f"The program {name} has been added to the whitelist.")

def add_to_blacklist(name):
    if name not in blacklist:
        blacklist.add(name)
        with open('blacklist.txt', 'a') as file:
            file.write(f"{name}\n")
        messagebox.showinfo("Success", f"The program {name} has been added to the blacklist.")

def get_network_processes():
    connections = psutil.net_connections(kind='all')
    pids = set(conn.pid for conn in connections if conn.pid is not None)
    
    processes = []
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            processes.append((proc.pid, proc.name(), proc.cmdline()))
        except psutil.NoSuchProcess:
            continue
    return processes

def show_process_details(event):
    selected_item = process_tree.focus()
    if selected_item:
        pid = process_tree.item(selected_item)['values'][0]
        try:
            process = psutil.Process(pid)
            path = process.exe()
            process_info = f"PID: {pid}\nName: {process.name()}\nPath: {path}\nArguments: {' '.join(process.cmdline())}"
            messagebox.showinfo("Process Details", process_info)
        except psutil.NoSuchProcess:
            messagebox.showerror("Error", f"The process with PID {pid} does not exist.")

def terminate_process(pid):
    try:
        process = psutil.Process(int(pid))
        process.terminate()
    except psutil.NoSuchProcess:
        messagebox.showerror("Error", f"The process {pid} does not exist.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while terminating the process:\n{e}")

def terminate_blacklisted_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] in blacklist:
            terminate_process(proc.info['pid'])

def display_network_processes(sort_by="pid"):
    check_admin()
    global refreshing, seen_processes, selected_pid

    load_whitelist()
    load_blacklist()

    selected_item = process_tree.focus()
    if selected_item:
        selected_pid = process_tree.item(selected_item)['values'][0]

    for row in process_tree.get_children():
        process_tree.delete(row)

    terminate_blacklisted_processes()

    network_processes = get_network_processes()

    for pid, name, cmdline in network_processes:
        if name not in seen_processes:
            if name not in whitelist:
                # Ustawienie okna jako zawsze na wierzchu przed wyświetleniem komunikatu
                root.attributes('-topmost', True)  
                response = messagebox.askyesno("New program", f"A new program has been detected: {name}. Do you want to run it?")
                root.attributes('-topmost', False)  # Przywracamy normalne zachowanie

                if response:
                    add_to_whitelist(name)
                else:
                    add_to_blacklist(name)
                    terminate_process(pid)
            seen_processes.add(name)

    sorted_processes = sorted(network_processes, key=lambda x: x[0] if sort_by == "pid" else x[1].lower())

    for pid, name, cmdline in sorted_processes:
        process_tree.insert("", "end", values=(pid, name))

    if selected_pid is not None:
        for item in process_tree.get_children():
            if process_tree.item(item)["values"][0] == selected_pid:
                process_tree.selection_set(item)
                process_tree.focus(item)
                break

    if refreshing:
        root.after(1000, display_network_processes, sort_by)

download_prev = psutil.net_io_counters().bytes_recv
upload_prev = psutil.net_io_counters().bytes_sent

def update_transfer_stats():
    global download_prev, upload_prev

    download_curr = psutil.net_io_counters().bytes_recv
    upload_curr = psutil.net_io_counters().bytes_sent

    download_speed = (download_curr - download_prev) / 1024 / 128  
    upload_speed = (upload_curr - upload_prev) / 1024 / 128  

    download_label.config(text=f"Download: {download_speed:.2f} MBit/s")
    upload_label.config(text=f"Upload: {upload_speed:.2f} MBit/s")

    download_prev = download_curr
    upload_prev = upload_curr

    if refreshing:
        root.after(1000, update_transfer_stats)

def get_local_ip():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        print(f'Wystąpił błąd przy uzyskiwaniu lokalnego IP: {e}')
        return None

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        ip_info = response.json()
        return ip_info['ip']
    except Exception as e:
        print(f'Wystąpił błąd: {e}')
        return None

root = tk.Tk()
root.title("Processes Using Network Connections")
root.configure(bg='#FFA500')  # Ustawienie tła okna na pomarańczowy
icon = Image.open(resource_path("icon.ico"))  # załaduj ikonę
root.iconphoto(False, ImageTk.PhotoImage(icon))  # użyj ikony

# Tworzenie stylu dla przycisków z pomarańczowym kolorem
style = ttk.Style()
style.configure('Orange.TButton', background='#FFA500', foreground='green')  # Kolor tła i tekstu
style.map('Orange.TButton', background=[('active', '#FF8C00')])  # Zmień kolor tła przy aktywacji
style.configure('Red.TButton', background='#FFA500', foreground='red')  # Kolor tła i tekstu
style.map('Red.TButton', background=[('active', '#FF8C00')])  # Zmień kolor tła przy aktywacji
style.configure('Nice.TButton', background='#FFA500', foreground='brown')  # Kolor tła i tekstu
style.map('Nice.TButton', background=[('active', '#FF8C00')])  # Zmień kolor tła przy aktywacji
# Tworzenie stylu dla zakładek
style = ttk.Style()
style.configure('TNotebook', background='orange')  # Ustaw kolor tła zakładki
style.configure('TNotebook.Tab', background='orange', padding=[10, 5])  # Ustaw kolor tła dla zakładek
style.map('TNotebook.Tab', background=[('selected', '#FFD700')])  # Ustaw kolor tła dla wybranej zakładki
notebook = ttk.Notebook(root)
notebook.pack(padx=10, pady=10, expand=True, fill='both')

process_tab = ttk.Frame(notebook)
notebook.add(process_tab, text="Processes ")

# Nowa zakładka "Blocked Apps"
blocked_apps_tab = ttk.Frame(notebook)
notebook.add(blocked_apps_tab, text="Blocked Apps")

# Utwórz listę zablokowanych aplikacji
blocked_apps_tree = ttk.Treeview(blocked_apps_tab, columns=("Name"), show="headings")
blocked_apps_tree.heading("Name", text="Blocked Applications")
blocked_apps_tree.pack(fill=tk.BOTH, expand=True)

def update_blocked_apps_list():
    # Usuwamy starą zawartość
    for row in blocked_apps_tree.get_children():
        blocked_apps_tree.delete(row)

    blocked_apps.clear()  # Czyszczenie zbioru zablokowanych aplikacji

    blocked_apps_file = "blocked_app_list"  # Podaj właściwą ścieżkę do pliku

    # Sprawdzanie, czy plik istnieje
    if not os.path.exists(blocked_apps_file):
        messagebox.showerror("Error", "The blocked apps list file does not exist.")
        return

    try:
        with open(blocked_apps_file, 'r', encoding='utf-8') as file:
            for line in file:
                program = line.strip()  # Usuwanie białych znaków
                if program:  # Sprawdzenie, czy linia nie jest pusta
                    blocked_apps.add(program)
                    blocked_apps_tree.insert("", "end", values=(program,))
    except FileNotFoundError:
        messagebox.showerror("Error", "The blocked apps list file was not found.")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred:\n{e}")

# Ustalenie aktualizacji listy zablokowanych aplikacji
update_blocked_apps_list()

# Przyciski w zakładce Blocked Apps
allow_process_button = ttk.Button(blocked_apps_tab, text="Allow Process", command=on_allow_blocked_process, style='Orange.TButton')
allow_process_button.pack(pady=10)

# Przycisk do odświeżania listy zablokowanych aplikacji
refresh_blocked_apps_button = ttk.Button(blocked_apps_tab, text="Refresh Blocked Apps", command=update_blocked_apps_list, style='Nice.TButton')
refresh_blocked_apps_button.pack(pady=10)

# Zakładka Transfers
transfer_tab = ttk.Frame(notebook)
notebook.add(transfer_tab, text="Transfers")

# Funkcja do testowania prędkości internetu z paskiem postępu
def test_speed():
    # Pokaż pasek i rozpocznij jego działanie
    #progress_bar.start()
    download_result_label.config(text="Testing...")
    upload_result_label.config(text="")
    ping_result_label.config(text="")
    
    # Użyj połączenia z prędkością i wynikami tutaj
    root.update()  # Uaktualnia interfejs, aby wyświetlił zmiany
    
    st = speedtest.Speedtest()
    st.download()
    st.upload()
    st.get_best_server()

    download_speed = st.results.download / 1_000_000  # przelicz na MBit/s
    upload_speed = st.results.upload / 1_000_000  # przelicz na MBit/s
    ping = st.results.ping
    
    # Zaktualizuj etykiety
    download_result_label.config(text=f"Max Download: {download_speed:.2f} MBit/s")
    upload_result_label.config(text=f"Max Upload: {upload_speed:.2f} MBit/s")
    ping_result_label.config(text=f"Ping: {ping} ms")
    
    # Zacznij od nowa na zakończenie testu
    progress_bar.stop()
    progress_bar.pack_forget()  # Ukryj pasek po zakończeniu

test_speed_button = ttk.Button(transfer_tab, text="Test your internet speed", command=test_speed, style='Nice.TButton')
test_speed_button.pack(pady=10)

download_result_label = ttk.Label(transfer_tab, text="Download speed N/A")
download_result_label.pack(pady=10)

upload_result_label = ttk.Label(transfer_tab, text="Upload speed: N/A")
upload_result_label.pack(pady=10)

ping_result_label = ttk.Label(transfer_tab, text="Ping: N/A")
ping_result_label.pack(pady=10)
ping_result_label.pack(pady=10)

# Zakładka Ports
ports_tab = ttk.Frame(notebook)
notebook.add(ports_tab, text="Ports")

port_label = ttk.Label(ports_tab, text="Port management")
port_label.grid(row=1, column=10, padx=5, pady=10)

# Etykieta i pole do wprowadzenia numeru portu
port_label = ttk.Label(ports_tab, text="Enter Port Number:")
port_label.grid(row=0, column=0, padx=5, pady=10)

port_entry = ttk.Combobox(ports_tab, values=["80", "443", "21"])
port_entry.grid(row=1, column=0, padx=5, pady=10)

# Etykieta i pole wyboru protokołu
protocol_var = tk.StringVar(value="TCP")  # Domyślnie ustawiony na TCP
protocol_combobox = ttk.Combobox(ports_tab, textvariable=protocol_var, values=["TCP", "UDP"])
protocol_combobox.grid(row=1, column=1, padx=5, pady=10)

# Przyciski do otwierania i zamykania portu
open_port_button = ttk.Button(ports_tab, text="Open Port", command=on_open_port, style='Orange.TButton')
open_port_button.grid(row=2, column=0, padx=5, pady=5)

close_port_button = ttk.Button(ports_tab, text="Close Port", command=on_close_port, style='Red.TButton')
close_port_button.grid(row=2, column=1, padx=5, pady=5)

port_label = ttk.Label(ports_tab, text="Port forwarding")
port_label.grid(row=4, column=10, padx=5, pady=10)

# Etykiety i pola do wprowadzenia adresów IP
ip1_label = ttk.Label(ports_tab, text="Enter Source IP:")
ip1_label.grid(row=3, column=0, padx=5, pady=10)

ip1_combobox = ttk.Combobox(ports_tab, values=["192.168.1.1", "10.0.0.1", "172.16.0.1"])
ip1_combobox.grid(row=4, column=0, padx=5, pady=10)

ip2_label = ttk.Label(ports_tab, text="Enter Destination IP:")
ip2_label.grid(row=3, column=1, padx=5, pady=10)

ip2_combobox = ttk.Combobox(ports_tab, values=["192.168.1.2", "10.0.0.2", "172.16.0.2"])
ip2_combobox.grid(row=4, column=1, padx=5, pady=10)

# Etykiety i pola do wprowadzenia portów
port1_label = ttk.Label(ports_tab, text="Enter Source Port:")
port1_label.grid(row=5, column=0, padx=5, pady=10)

port1_combobox = ttk.Combobox(ports_tab, values=["8080", "9000", "5000"])
port1_combobox.grid(row=6, column=0, padx=5, pady=10)

port2_label = ttk.Label(ports_tab, text="Enter Destination Port:")
port2_label.grid(row=5, column=1, padx=5, pady=10)

port2_combobox = ttk.Combobox(ports_tab, values=["8081", "9001", "5001"])
port2_combobox.grid(row=6, column=1, padx=5, pady=10)

# Przycisk do przekierowania portu
redirect_port_button = ttk.Button(ports_tab, text="Redirect Port", command=lambda: redirect_port(), style='Nice.TButton')
redirect_port_button.grid(row=7, column=0, padx=5, pady=10, columnspan=2)

# Zakładka IP
proxy_tab = ttk.Frame(notebook)
notebook.add(proxy_tab, text="IP")

# Etykieta i pole do wprowadzenia domeny
domain_label = ttk.Label(proxy_tab, text="Enter Domain Name:")
domain_label.grid(row=0, column=0, padx=5, pady=10)

domain_entry = ttk.Entry(proxy_tab)
domain_entry.grid(row=0, column=1, padx=5, pady=10)

# Etykieta do wyświetlania adresu IP
ip_result_label = ttk.Label(proxy_tab, text="IP Address: N/A")
ip_result_label.grid(row=1, column=0, columnspan=2, padx=5, pady=10)

# Funkcja do wyszukiwania adresu IP na podstawie domeny
def lookup_ip():
    domain = domain_entry.get()
    if not domain:
        messagebox.showwarning("Warning", "Please enter domain name.")
        return
    try:
        ip_address = socket.gethostbyname(domain)
        ip_result_label.config(text=f"IP Address: {ip_address}")
        
        # Dodaj informację o geolokalizacji
        location_info = geolocate_ip(ip_address)
        geolocation_label.config(text=location_info)  # zaktualizuj etykietę
        messagebox.showinfo("Geolocation Info", location_info)
    except socket.error as e:
        messagebox.showerror("Error", f"An error occurred while searching for an Ip address:\n{e}")
# Funkcja do skanowania portów
# 30 najpopularniejszych portów
popular_ports = [
    21,  # FTP
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS
    67,  # DHCP
    68,  # DHCP
    80,  # HTTP
    110, # POP3
    137, # netbios
    138, # netbios Alternate
    139, # netbios Alternate
    143, # IMAP
    443, # HTTPS
    631, # CUPS
    3128,# Squid
    3306,# MySQL
    3389,# RDP
    4000,# NX
    8080,# HTTP Alternate
    8081,# HTTP Alternate
    5432,# PostgreSQL
    5900,# VNC
    6379,# Redis
    9200,# Elasticsearch
    27017,# MongoDB
    5000,# Flask
    8000 # Common HTTP Alternative
]

# Funkcja do skanowania portów
def scan_ports():
    ip_address = ip_result_label.cget("text").split(": ")[1]  # Pobierz adres IP
    if ip_address == "N/A":
        messagebox.showwarning("Warning", "First, search for the IP address.")
        return

    open_ports = []

    for port in popular_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)  # Ustaw timeout na 100ms
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append(port)

    if open_ports:
        messagebox.showinfo("Open Ports", f"Open ports on {ip_address}--->> {', '.join(map(str, open_ports))}")
    else:
        messagebox.showinfo("Open Ports", f"No open ports on {ip_address}.")

# Przycisk do skanowania portów
scan_ports_button = ttk.Button(proxy_tab, text="Port scan", command=scan_ports, style='Nice.TButton')
scan_ports_button.grid(row=0, column=2, padx=5, pady=10)

# Przycisk do wyszukiwania adresu IP
lookup_button = ttk.Button(proxy_tab, text="Search IP", command=lookup_ip, style='Nice.TButton')
lookup_button.grid(row=0, column=3, padx=5, pady=10)

# Etykieta do wyświetlania wyników geolokalizacji
geolocation_label = ttk.Label(proxy_tab, text="Geolocation results: N/A")
geolocation_label.grid(row=3, column=0, columnspan=2, padx=5, pady=10)


description_tab = ttk.Frame(notebook)
notebook.add(description_tab, text="Info")

style = ttk.Style()
style.configure('Tab.TFrame', background='#FFA500') 

process_frame = tk.Frame(process_tab, bg='#FFA500')  # Ustawienie tła zakładki
process_frame.pack(padx=0, pady=0, fill='both', expand=True)

columns = ("PID", "Name")
process_tree = ttk.Treeview(process_frame, columns=columns, show="headings", style='Treeview')
process_tree.heading("PID", text="PID", command=lambda: display_network_processes(sort_by="pid"))
process_tree.heading("Name", text="Name", command=lambda: display_network_processes(sort_by="name"))
process_tree.pack(side=tk.LEFT, fill='both', expand=True)

scrollbar = ttk.Scrollbar(process_frame, orient="vertical", command=process_tree.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

process_tree.configure(yscrollcommand=scrollbar.set)

process_tree.bind("<Double-1>", show_process_details)

# Zmiana umiejscowienia przycisków "Allow Process" i "Block Process"
button_frame = ttk.Frame(process_tab)
button_frame.pack(pady=10)  # Umieszczamy kontener w oknie

block_internet_button = ttk.Button(button_frame, text="Block Process", command=on_block_internet, style='Red.TButton')
block_internet_button.grid(row=0, column=1, padx=5)  # Użyj `grid`, aby umieścić przycisk w drugiej kolumnie

public_ip_label = ttk.Label(transfer_tab, text="Public IP: N/A", background='#FFA500')
public_ip_label.pack(pady=10)

local_ip_label = ttk.Label(transfer_tab, text="Local IP: N/A", background='#FFA500')
local_ip_label.pack(pady=10)

download_label = ttk.Label(transfer_tab, text="Download: 0.00 Mbit/s", background='#FFA500')
download_label.pack(pady=10)

upload_label = ttk.Label(transfer_tab, text="Upload: 0.00 Mbit/s", background='#FFA500')
upload_label.pack(pady=10)

description_text = (
    "Program Function Description:\n"
    "-*Process Monitoring:** The application continuously scans for all processes\n"
    "   activity, allowing you to keep an eye on what is using your bandwidth.\n"
    
    "-*Internet Access Control:** Users can block or allow internet access. This\n"
    "   feature is particularly useful for preventing unwanted applications from\n"
    "   accessing the internet while allowing necessary ones to continue\n"
    "   functioning.\n"
    
    "-*Whitelist and Blacklist Management:** The program enables you to maintain\n"
    "   lists that are allowed (whitelist) or denied (blacklist) access. This\n"
    "   facilitates organization and ensures that critical apps are not mistakenly\n"
    "   blocked.\n"
    
    "-*Internet Speed Testing:** The application integrates with speedtest.net for\n"
    "   internet speed testing. It measures both download and upload speeds.\n"
    
    "-*Data Transfer Statistics:** It tracks data transfer, allowing you to monitor\n"
    "   download and upload speeds in real-time, helping to gauge the performance\n"
    "   of your internet connection effectively.\n"
    
    "-*Geolocation Features:** By entering a domain name, users can retrieve the\n"
    "   IP address along with geolocation information, making it easier to\n"
    "   understand the source of the network traffic.\n"
    
    "-*Port Management:** The application allows users to open and close specific\n"
    "   ports and redirect traffic from one port to another. This is useful for\n"
    "   troubleshooting network issues or configuring network services.\n"
)


description_label = ttk.Label(description_tab, text=description_text, justify="left", anchor="nw", background='#FFA500')
description_label.pack(padx=0, pady=0)

# Uzyskiwanie lokalnego IP na początku i aktualizowanie etykiety
local_ip = get_local_ip()
local_ip_label.config(text=f"Local IP: {local_ip or 'Failed to download'}")

# Uzyskiwanie publicznego IP na początku
public_ip = get_public_ip()
public_ip_label.config(text=f"Public IP: {public_ip or 'Failed to download'}")

# Ładowanie whitelisty i blacklisty na początku
load_whitelist()
load_blacklist()
display_network_processes(sort_by="pid")

# Uruchamiamy aktualizację transferu
update_transfer_stats()

# Ustalamy, co się stanie, gdy aplikacja jest zamykana
def on_closing():
    if messagebox.askokcancel("Quit", "Are you sure you want to close the application?"):
        root.destroy()  # Zniszczenie okna i zakończenie programu

# Dodaj tę linię, aby przypisać funkcję do zdarzenia zamykania okna
root.protocol("WM_DELETE_WINDOW", on_closing)

# Rozpoczęcie głównej pętli
root.mainloop()
