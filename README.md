# OzRipper

OzRipper, güçlü ve kapsamlı bir brute force aracı ve hash kırıcıdır. HTTP form tabanlı brute force saldırıları yapabilir ve çeşitli hash algoritmalarını kırmak için kullanılabilir.

## Özellikler

- HTTP GET form brute force saldırıları
- MD5, SHA-1 ve SHA-256 hash algoritmaları desteği
- Çoklu thread desteği
- Verbose mod ile detaylı çıktı
- Hash kırma ve HTTP form brute force için parametreler

## Kullanım

### HTTP Form Brute Force
Örnek Kulanım: ./ozripper 192.168.1.1 -l users.txt -p passwords.txt http-get-form "/
login:username=^USER^&password=^PASS^&submit=Login:F=Invalid username or password"

# Hash Kırma: ./ozripper -h [hash] -t [hash_türü] -p [parola_listesi]

### Örnek Hash Kırma ./ozripper -h 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -p passwords.txt

 # Parametleler
-l: Kullanıcı adı veya kullanıcı listesi yolu
-p: Parola veya parola listesi yolu
-h: Kırılacak hash değeri
-t: Hash türü (md5, sha1, sha256)
-v: Verbose mod (detaylı çıktı)
http-get-form: HTTP GET form brute force saldırısı türü

Kurulum

GitHub deposunu klonlayın: git clone [https://github.com/kullanici_adi/ozripper.git]

Depoya Gidin: cd ozripper

## Derleyin: make

## Lisans
Bu proje MIT Lisansı altında lisanslanmıştır. Daha fazla bilgi için LICENSE dosyasına bakabilirsiniz.

## OzRipperin hikayesi
OzRipper 2023 senesinin 24nisanında çok sevdim bir kardeşimin vefatı nedeniyle ozanripper adı verilmistir.  24.04.∞
