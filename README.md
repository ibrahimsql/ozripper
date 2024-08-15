#🔓 OZRipper: Güçlü ve Esnek Hash Kırma Aracı

 
OZRipper, MD5, SHA1, SHA256 ve SHA512 hash değerlerini çözmek için tasarlanmış güçlü ve esnek bir araçtır. Bu araç, parola listeleri kullanarak hash çözer ve HTTP GET veya POST form tabanlı saldırılar için kapsamlı destek sunar. Ayrıca, iki faktörlü kimlik doğrulama (2FA) ve çoklu iş parçacığı desteği ile gelişmiş bir kullanıcı deneyimi sağlar.

## 🌟 Özellikler
Desteklenen Hash Türleri: MD5, SHA1, SHA256 ve SHA512
Parola Listesi ile Hash Çözme: Parola listeleri kullanarak hash değerlerini kırma
HTTP GET ve POST Form Tabanlı Saldırılar: Web formlarına yönelik GET ve POST saldırıları
İki Faktörlü Kimlik Doğrulama (2FA) Desteği: 2FA korumalı oturumlar için destek
Çoklu İş Parçacığı Desteği: Performansı artıran çoklu iş parçacığı kullanımı
Ayrıntılı Çıktı Modu: Detaylı sonuçlar ve kapsamlı loglama

### 🔧 Gereksinimler
libssl-dev: SSL/TLS işlemleri için gerekli kütüphane
libcurl4-openssl-dev: URL işlemleri ve HTTP protokolleri için gerekli kütüphane
### 🚀 Kurulum
1. GitHub Deposunu Klonlayın
2. git clone https://github.com/ibrahimsql/ozripper.git
cd ozripper

2. Gerekli Kütüphaneleri Yükleyin
sudo apt-get install libssl-dev libcurl4-openssl-dev

3. Derleme
gcc -o ozripper ozripper.c -lssl -lcrypto -lpthread -lcurl

## 🛠️ Kullanım
**HTTP Form Brute Force**
Örnek Kullanım:
ozripper 192.168.1.1 -l users.txt -p passwords.txt http-get-form "/login:username=^USER^&password=^PASS^&submit=Login:F=Invalid username or password"
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v

**HTTP GET Form**
ozripper <target_ip> -l <username_list.txt> -p <password_list.txt> http-get-form "<form_path>:<form_fields>:F=<error_message>" [-v]

**HTTP POST Form**
ozripper <target_ip> -l <username_list.txt> -p <password_list.txt> http-post-form "<form_path>:<form_fields>:F=<error_message>" [-v]

**Kullanıcı ve Parola Listesi ile HTTP GET Form Saldırısı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v

**Daha Karmaşık Form Alanları ile HTTP GET Form Saldırısı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:user=&pass=&submit=Login:F=Invalid login" -f "user=&pass=&submit=Login" -v

**İki Faktörlü Kimlik Doğrulama (2FA) ile HTTP Form Saldırısı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -o otp_code -v

**Kullanıcı ve Parola Listesi ile HTTP POST Form Saldırısı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -m POST -v

### PROXYCHAİNS KULLANIMLARI

**GET Form ile Proxy Kullanımı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -x http://proxy:port

**GET Form ile Proxychains Kullanımı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -y proxychains.conf

**GET Form ile Timeout Ayarı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -t 60

**POST Form ile Proxy Kullanımı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -m POST -v -x http://proxy:port

**POST Form ile Proxychains Kullanımı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -m POST -v -y proxychains.conf

**POST Form ile Timeout Ayarı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -m POST -v -t 60

### HASH KIRMA

**MD5 Hash Kırma**
ozripper -h <md5_hash> -p <password_list.txt> -t md5 [-v]
ozripper -h 5d41402abc4b2a76b9719d911017c592 -p passwords.txt -t md5 -v

**SHA1 Hash Kırma**
ozripper -h <sha1_hash> -p <password_list.txt> -t sha1 [-v]
ozripper -h 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 -p passwords.txt -t sha1 -v

**SHA256 Hash Kırma**
ozripper -h <sha256_hash> -p <password_list.txt> -t sha256 [-v]
ozripper -h e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -p passwords.txt -t sha256 -v

**SHA512 Hash Kırma**
ozripper -h <sha512_hash> -p <password_list.txt> -t sha512 [-v]
ozripper -h cf83e1357eefb8bd... -p passwords.txt -t sha512 -v

### İki Faktörlü Kimlik Doğrulama (2FA) Kırma Örnekleri

**Basit 2FA Kırma (GET Form)**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=&otp=:F=Invalid login:2FA=otp" -o otp_codes.txt -m GET -v

**2FA ile Proxy Kullanımı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=&otp=:F=Invalid login:2FA=otp" -o otp_codes.txt -m GET -v -x http://proxy:port

**2FA ile Proxychains Kullanımı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=&otp=:F=Invalid login:2FA=otp" -o otp_codes.txt -m GET -v -y proxychains.conf

**2FA ile Timeout Ayarı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=&otp=:F=Invalid login:2FA=otp" -o otp_codes.txt -m GET -v -t 60

### ⚙️ Karmaşık Kullanım Senaryoları
**Karmaşık GET Form ve POST Form Kombinasyonu**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -t 30 -x http://proxy:port
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=:F=Invalid login" -m POST -v -t 30 -y proxychains.conf

**Birden Fazla Proxy ile Saldırı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -p proxy_list.txt -t 30

**İş Parçacığı Kullanımı ile Saldırı**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -m GET -v -t 30 -t 16

**Hash Kırma ve 2FA Kombinasyonu**
ozripper 192.168.1.1 -l usernames.txt -p passwords.txt http-post-form "/login.php:username=&password=&otp=:F=Invalid login:2FA=otp" -o otp_codes.txt -m POST -v -t 30 -x http://proxy:port
ozripper -h e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -p passwords.txt -t sha256 -v -x http://proxy:port -t 30

### 📜 Tam Kullanım Kılavuzu
ozripper <hedef_ip> -l <kullanıcı_listesi> -p <parola_listesi> <saldırı_türü> "[sayfa_yolu]:[form_alanları]:F=[hata_mesajı]" [-v] [-h -t <hash_türü>] [-m] [-f <form_alanları>] [-o <otp_form>] [-t <iş_parçacığı_sayısı>]


#### Parametreler ve Açıklamaları
`<target_ip>: Hedef IP adresi.
`-l <username_list.txt>: Kullanıcı adı listesinin bulunduğu dosya.
`-p <password_list.txt>: Parola listesinin bulunduğu dosya.
`http-get-form: GET form saldırısı yapacağını belirtir.
`http-post-form: POST form saldırısı yapacağını belirtir.
`<form_path>: Formun yolu.
`<form_fields>: Form alanları.
`F=<error_message>: Hata mesajı.
`-h <hash>: Kırılacak hash değeri.
`-t <hash_type>: Hash türü (md5, sha1, sha256, sha512).
`-v: Ayrıntılı çıktı.
`-m <metod>: HTTP metodunu belirtir (GET veya POST).
`-f <form_fields>: Form alanları.
`-o <otp_form>: OTP formu (isteğe bağlı).
`-x <proxy>: Proxy adresi (isteğe bağlı).
`-y <proxychains>: Proxychains konfigürasyon dosyası (isteğe bağlı).
`-t <timeout>: Timeout süresi (saniye).
`-p <proxy_listesi>: Birden fazla proxy listesi.
`-t <iş_parçacığı_sayısı>: İş parçacığı sayısı.


### 🛠️ Kurulum

**GitHub Deposunu Klonlayın:**
git clone https://github.com/ibrahimsql/ozripper.git
cd ozripper

**Gerekli Kütüphaneleri Yükleyin**
sudo apt-get install libssl-dev libcurl4-openssl-dev

**Derleyin**
gcc -o ozripper ozripper.c -lssl -lcrypto -lpthread -lcurl


## 🤝 Katkıda Bulunma
Katkılar her zaman memnuniyetle karşılanır! Herhangi bir değişiklik yapmak isterseniz, lütfen bir konu açın veya bir çekme isteği gönderin.

## 📝 Lisans
Bu proje MIT lisansı altında lisanslanmıştır. Daha fazla bilgi için LISANS dosyasına bakın.

## 📬 İletişim
Proje ile ilgili sorularınız için [ib433503@gmail.com](mailto:ib433503@gmail.com) adresine ulaşabilirsiniz.

## 🏆 OzRipper’in Hikayesi
OzRipper, adını, çok sevdiğim kardeşim Ozan’ın anısından alır. Ozan, 24 Nisan 2023 tarihinde vefat etti ve bu kaybın ardından onun anısını yaşatmak için bu projeyi başlattım. Projemizin adı, Ozan’ın mirasını yaşatmak ve onun hatırasına saygı göstermek amacıyla bu yazılımın her bir parçasında yaşatılmaktadır.
OzRipper, güçlü bir hash kırma aracı olarak teknik dünyada iz bırakmakla kalmayıp, aynı zamanda Ozan’ın azmi ve ilham verici kişiliğini de anmak için tasarlandı. Her bir satır kodda, onun hatırasına olan bağlılığımızı ve yaşamış olduğu özveriyi yansıtmayı umuyoruz.
Bu proje, sadece bir yazılım aracı değil, aynı zamanda kaybettiğimiz değerli bir insanın anısını onurlandırma çabamızın bir sembolüdür. Kalbimizdesin, Ozan kardeşim. 24.04.∞
