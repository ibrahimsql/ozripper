# Ozripper

Ozripper, MD5, SHA1, SHA256 ve SHA512 hash değerlerini kırmak için kullanılan bir araçtır. Bu araç, belirtilen hash değerini, bir parola listesi kullanarak çözer ve HTTP GET veya POST form tabanlı saldırıları destekler.

## Özellikler

- MD5, SHA1, SHA256 ve SHA512 hash türleri desteği
- Parola listesi ile hash çözme
- HTTP GET ve POST form tabanlı saldırı desteği
- İki Faktörlü Kimlik Doğrulama (2FA) desteği
- Çoklu iş parçacığı desteği
- Ayrıntılı çıktı modu

## Gereksinimler

- libssl-dev
- libcurl4-openssl-dev

## Kurulum

1. GitHub deposunu klonlayın:
   ```sh
   git clone https://github.com/ibrahimsql/ozripper.git
## Depoya gidin:
cd ozripper

## Gerekli kütüphaneleri yükleyin:
sudo apt-get install libssl-dev libcurl4-openssl-dev

## Derleyin: gcc -o ozripper ozripper.c -lssl -lcrypto -lpthread -lcurl

## Kullanım
## HTTP Form Brute Force
Örnek Kulanım: ozripper 192.168.1.1 -l users.txt -p passwords.txt http-get-form "/ login:username=^USER^&password=^PASS^&submit=Login:F=Invalid username or password"
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v

## HTTP GET Form
ozripper <target_ip> -l <username_list.txt> -p <password_list.txt> http-get-form "<form_path>:<form_fields>:F=<error_message>" [-v]

## HTTP POST Form
ozripper <target_ip> -l <username_list.txt> -p <password_list.txt> http-post-form "<form_path>:<form_fields>:F=<error_message>" [-v]

## Kullanıcı ve Parola Listesi ile HTTP GET Form Saldırısı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v

## Daha Karmaşık Form Alanları ile HTTP GET Form Saldırısı
## ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:user=&pass=&submit=Login:F=Invalid login" -f "user=&pass=&submit=Login" -v

## İki Faktörlü Kimlik Doğrulama (2FA) ile HTTP Form Saldırısı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -o otp_code -v
 
## Kullanıcı ve Parola Listesi ile HTTP POST Form Saldırısı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -m POST -v

## Daha Karmaşık Form Alanları ile HTTP GET Form Saldırısı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:user=&pass=&submit=Login:F=Invalid login" -f "user=&pass=&submit=Login" -v####
## ProxyChains
### GET Form ile Proxy Kullanımı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -x http://proxy:port

### GET Form ile Proxychains Kullanım
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -y proxychains.conf

### GET Form ile Timeout Ayarı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -t 60

**HTTP POST Form** Saldırısı Örnekleri
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -m POST -v
### POST Form ile Proxy Kullanımı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -m POST -v -x http://proxy:port

### POST Form ile Proxychains Kullanımı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -m POST -v -y proxychains.conf

### POST Form ile Timeout Ayarı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -m POST -v -t 60
 
## HASH KIRMA 
## Örnek Hash Kırma (MD5,SHA1,SHA256,SHA512)
## MD5 Hash Kırma/ MD5 Hash Kırma (Parola Listesi ile)
ozripper -h <md5_hash> -p <password_list.txt> -t md5 [-v]
ozripper -h 5d41402abc4b2a76b9719d911017c592 -p passwords.txt -t md5 -v

## SHA1 Hash Kırma/SHA1 Hash Kırma (Parola Listesi ile)
ozripper -h <sha1_hash> -p <password_list.txt> -t sha1 [-v]
ozripper -h 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 -p passwords.txt -t sha1 -v

## SHA256 Hash Kırma/SHA256 Hash Kırma (Parola Listesi ile)
ozripper -h <sha256_hash> -p <password_list.txt> -t sha256 [-v]
ozripper -h e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -p passwords.txt -t sha256 -v

### SHA512 Hash Kırma
ozripper -h cf83e1357eefb8bd... (SHA512 hash) -p passwords.txt -t sha512 -v


## İki Faktörlü Kimlik Doğrulama (2FA) Kırma Örnekleri
### Basit 2FA Kırma (GET Form)
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=&otp=:F=Invalid login:2FA=otp" -o otp_codes.txt -m GET -v

## 2FA ile Proxy Kullanımı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=&otp=:F=Invalid login:2FA=otp" -o otp_codes.txt -m GET -v -x http://proxy:port

## 2FA ile Proxychains Kullanımı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=&otp=:F=Invalid login:2FA=otp" -o otp_codes.txt -m GET -v -y proxychains.conf

## 2FA ile Timeout Ayarı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=&otp=:F=Invalid login:2FA=otp" -o otp_codes.txt -m GET -v -t 60


# Karmaşık Kullanım Senaryoları
### Karmaşık GET Form ve POST Form Kombinasyonu
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -t 30 -x http://proxy:port
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -m POST -v -t 30 -y proxychains.conf

## Birden Fazla Proxy ile Saldırı

ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -p proxy_list.txt -t 30

## İş Parçacığı Kullanımı ile Saldırı
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -t 30 -t 16

## Hash Kırma ve 2FA Kombinasyonu
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=&otp=:F=Invalid login:2FA=otp" -o otp_codes.txt -m POST -v -t 30 -x http://proxy:port
ozripper -h e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -p passwords.txt -t sha256 -v -x http://proxy:port -t 30


# Tam Kullanım Kılavuzu
ozripper <hedef_ip> -l <kullanıcı_listesi> -p <parola_listesi> <saldırı_türü> "[sayfa_yolu]:[form_alanları]:F=[hata_mesajı]" [-v] [-h -t <hash_türü>] [-m] [-f <form_alanları>] [-o <otp_form>] [-t <iş_parçacığı_sayısı>]

## Parametleler Ve Açıklamları
<target_ip>: Hedef IP adresi.
-l <username_list.txt>: Kullanıcı adı listesinin bulunduğu dosya.
-p <password_list.txt>: Parola listesinin bulunduğu dosya.
http-get-form: GET form saldırısı yapacağını belirtir.
http-post-form: POST form saldırısı yapacağını belirtir.
<form_path>: Formun yolu.
<form_fields>: Form alanları.
F=<error_message>: Hata mesajı.
-h <hash>: Kırılacak hash değeri.
-t <hash_type>: Hash türü (md5, sha1, sha256, sha512).
-v: Ayrıntılı çıktı.
-m <metod>: HTTP metodunu belirtir (GET veya POST).
-f <form_fields>: Form alanları.
-o <otp_form>: OTP formu (isteğe bağlı).
-x <proxy>: Proxy adresi (isteğe bağlı).
-y <proxychains>: Proxychains konfigürasyon dosyası (isteğe bağlı).
-t <timeout>: Timeout süresi (saniye).
-p <proxy_listesi>: Birden fazla proxy listesi.
-t <iş_parçacığı_sayısı>: İş parçacığı sayısı.
# Kurulum
GitHub deposunu klonlayın: git clone [https://github.com/ibrahimsql/ozripper.git]

## Depoya Gidin: cd ozripper

## Gerekli kütüphaneleri yükleyin:

sudo apt-get install libssl-dev libcurl4-openssl-dev

## Derleyin: gcc -o ozripper ozripper.c -lssl -lcrypto -lpthread -lcurl

## Katkıda Bulunma
Katkıda bulunmak istiyorsanız, lütfen bir pull request gönderin veya issue açın.

### Lisans
Bu proje MIT Lisansı altında lisanslanmıştır. Daha fazla bilgi için LICENSE dosyasına bakabilirsiniz.
### İletişim
Proje ile ilgili sorularınız için ib433503@gmail.com adresine ulaşabilirsiniz.

## OzRipperin hikayesi
OzRipper 2023 senesinin 24nisanında çok sevdim bir kardeşimin vefatı nedeniyle ozanripper adı verilmistir.  24.04.∞

