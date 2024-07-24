# Ozripper

Ozripper, MD5, SHA1 ve SHA256 hash değerlerini kırmak ve HTTP GET veya POST form tabanlı saldırılar gerçekleştirmek için kullanılan bir araçtır. Ayrıca iki faktörlü kimlik doğrulama (2FA) desteği de eklenmiştir.

## Özellikler

- **MD5, SHA1 ve SHA256 hash türleri desteği**
- **Parola listesi ile hash çözme**
- **HTTP GET ve POST form tabanlı saldırı desteği**
- **Çoklu iş parçacığı desteği**
- **Ayrıntılı çıktı modu**
- **İki faktörlü kimlik doğrulama (2FA) desteği**
- **Proxychains entegrasyonu**

## Gereksinimler

- **libssl-dev**
- **libcurl4-openssl-dev**

## Kurulum

1. GitHub deposunu klonlayın:
    ```sh
    git clone https://github.com/ibrahimsql/ozripper.git
    ```

2. Depoya gidin:
    ```sh
    cd ozripper
    ```

3. Gerekli kütüphaneleri yükleyin:
    ```sh
    sudo apt-get install libssl-dev libcurl4-openssl-dev
    ```

4. Derleyin:
    ```sh
    gcc -o ozripper ozripper.c -lssl -lcrypto -lpthread -lcurl
    ```

## Kullanım

### HTTP Form Brute Force

**Temel Kullanım:**
```sh
ozripper <target_ip> -l <username_list.txt> -p <password_list.txt> http-get-form "<form_path>:<form_fields>:F=<error_message>" [-v] [-m <method>] [-f <form_fields>] [-o <otp_form>] [-t <thread_count>]

### HTTP GET Form
## Temel Kullanım:
ozripper <target_ip> -l <username_list.txt> -p <password_list.txt> http-get-form "<form_path>:<form_fields>:F=<error_message>" [-v]
**Örnek Kullanım:**
ozripper 192.168.1.1 -l users.txt -p passwords.txt http-get-form "/login.php:username=&password=:F=Invalid login" -v
## HTTP POST Form


