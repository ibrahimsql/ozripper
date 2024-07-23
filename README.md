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

```bash
./ozripper [hedef_ip] -l [kullanıcı_listesi] -p [parola_listesi] http-get-form "[sayfa_yolu]:[form_bilgisi]:F=[hata_mesajı]"
OzRipper 2023 senesinin 24nisanında çok sevdim bir kardeşimin vefatı nedeniyle ozanripper adı verilmistir.
