# Ozripper

Ozripper, MD5, SHA1 ve SHA256 hash değerlerini kırmak için kullanılan bir araçtır. Bu araç, belirtilen hash değerini, bir parola listesi kullanarak çözer ve HTTP GET veya POST form tabanlı saldırıları destekler.

## Özellikler

- MD5, SHA1 ve SHA256 hash türleri desteği
- Parola listesi ile hash çözme
- HTTP GET ve POST form tabanlı saldırı desteği
- Çoklu iş parçacığı desteği
- Ayrıntılı çıktı modu

## Gereksinimler

- `libssl-dev`
- `libcurl4-openssl-dev`
- 
# Kullanım 
### HTTP Form Brute Force
Örnek Kulanım: ozripper 192.168.1.1 -l users.txt -p passwords.txt http-get-form "/
login:username=^USER^&password=^PASS^&submit=Login:F=Invalid username or password"
## HTTP GET Form
ozripper <target_ip> -l <username_list.txt> -p <password_list.txt> http-get-form "<form_path>:<form_fields>:F=<error_message>" [-v]
## HTTP POST Form
ozripper <target_ip> -l <username_list.txt> -p <password_list.txt> http-post-form "<form_path>:<form_fields>:F=<error_message>" [-v]
## Kullanıcı ve Parola Listesi ile HTTP GET Form Saldırısı 
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=<username>&password=<password>:F=Invalid login" -m GET -v
## Kullanıcı ve Parola Listesi ile HTTP POST Form Saldırısı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=<username>&password=<password>:F=Invalid login" -m POST -v
##  Daha Karmaşık Form Alanları ile HTTP GET Form Saldırısı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:user=<username>&pass=<password>&submit=Login:F=Invalid login" -f "user=<username>&pass=<password>&submit=Login" -v


### Örnek Hash Kırma (MD5,SHA1,SHA256,SHA512)

### MD5 Hash Kırma/ MD5 Hash Kırma (Parola Listesi ile)
ozripper -h <md5_hash> -p <password_list.txt> -t md5 [-v] 
ozripper -h 5d41402abc4b2a76b9719d911017c592 -p passwords.txt -t md5 -v

### SHA1 Hash Kırma/SHA1 Hash Kırma (Parola Listesi ile)
ozripper -h <sha1_hash> -p <password_list.txt> -t sha1 [-v]
ozripper -h 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 -p passwords.txt -t sha1 -v

### SHA256 Hash Kırma/SHA256 Hash Kırma (Parola Listesi ile) 
ozripper -h <sha256_hash> -p <password_list.txt> -t sha256 [-v]
ozripper -h e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -p passwords.txt -t sha256 -v

## Tam Kullanım Kılavuzu
ozripper <hedef_ip> -l <kullanıcı_listesi> -p <parola_listesi> <saldırı_türü> "[sayfa_yolu]:[form_alanları]:F=[hata_mesajı]" [-v] [-h <hash> -t <hash_türü>] [-m <metod>] [-f <form_alanları>] [-t <iş_parçacığı_sayısı>]


 # Parametleler Ve Açıklamları
<target_ip>: Hedef IP adresi.
-l <username_list.txt>: Kullanıcı adı listesinin bulunduğu dosya.
-p <password_list.txt>: Parola listesinin bulunduğu dosya.
http-get-form: GET form saldırısı yapacağını belirtir.
http-post-form: POST form saldırısı yapacağını belirtir.
<form_path>: Formun yolu.
<form_fields>: Form alanları.
F=<error_message>: Hata mesajı.
-h <hash>: Kırılacak hash değeri.
-t <hash_type>: Hash türü (md5, sha1, sha256).
-v: Ayrıntılı çıktı.
-m <method>: HTTP metodunu belirtir (GET veya POST).
-f <form_fields>: Form alanlar
## Kurulum

GitHub deposunu klonlayın: git clone [https://github.com/ibrahimsql/ozripper.git]

Depoya Gidin: cd ozripper

Gerekli kütüphaneleri yükleyin:

```sh
sudo apt-get install libssl-dev libcurl4-openssl-dev

## Derleyin: gcc -o ozripper ozripper.c -lssl -lcrypto -lpthread -lcurl

## Katkıda Bulunma
Katkıda bulunmak istiyorsanız, lütfen bir pull request gönderin veya issue açın.

### Lisans
Bu proje MIT Lisansı altında lisanslanmıştır. Daha fazla bilgi için LICENSE dosyasına bakabilirsiniz.
### İletişim
Proje ile ilgili sorularınız için example@example.com adresine ulaşabilirsiniz.

## OzRipperin hikayesi
OzRipper 2023 senesinin 24nisanında çok sevdim bir kardeşimin vefatı nedeniyle ozanripper adı verilmistir.  24.04.∞
