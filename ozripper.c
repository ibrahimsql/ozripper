#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/sha512.h>

#define MAX_WORD_LEN 256
#define MAX_URL_LEN 1024
#define MAX_MSG_LEN 1024
#define BUFFER_SIZE 2048

typedef enum {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256,
    HASH_SHA512,
    HASH_UNKNOWN
} hash_type_t;

typedef struct {
    char *target_ip; // Hedef IP adresi
    char *username_list; // Kullanıcı adı listesi
    char *password_list; // Şifre listesi
    char *attack_type; // Saldırı türü
    char *form_info; // Form bilgileri
    char *error_message; // Hata mesajı
    char *hash; // Kırılacak hash
    hash_type_t hash_type; // Hash türü
    int thread_id; // İş parçacığı kimliği
    int num_threads; // İş parçacığı sayısı
    int verbose; // Ayrıntılı çıktı
    char *method; // HTTP metodunu belirtir
    char *form_fields; // Form alanları
    char *otp_codes_file; // 2FA kodlarının bulunduğu dosya
    char *proxy; // Proxy ayarı
    char *proxychains_conf; // Proxychains yapılandırması
    int timeout; // İstek zaman aşımı
    // Yeni parametreler
    char *input_file; // Girdi dosyası
    char *output_file; // Çıktı dosyası
    char *output_format; // Çıktı formatı
    int single_hash; // Tek hash modu
    int batch_mode; // Toplu işlem modu
    int interactive_mode; // Etkileşimli mod
    int silent_mode; // Sessiz mod
    int verbose_mode; // Ayrıntılı mod
    int progress_bar; // İlerleme çubuğu
    int brute_force; // Kaba kuvvet modu
    char *dictionary; // Sözlük dosyası
    char *wordlist; // Kelime listesi
    int min_length; // Minimum kelime uzunluğu
    int max_length; // Maksimum kelime uzunluğu
    char *charset; // Karakter seti
    int incremental; // Artan mod
    char *mask; // Maske
    char *attack_mode; // Saldırı modu
    int threads; // İş parçacığı sayısı
    int gpu; // GPU kullanımı
    int priority; // Öncelik
    char *memory_limit; // Bellek limiti
    int skip_errors; // Hataları atla
    int retry; // Tekrar deneme sayısı
    char *rules; // Kurallar
    char *exclude_chars; // Hariç tutulan karakterler
    char *include_chars; // Dahil edilen karakterler
    int min_numbers; // Minimum rakam sayısı
    int min_uppercase; // Minimum büyük harf sayısı
    int min_lowercase; // Minimum küçük harf sayısı
    int max_non_alpha; // Maksimum alfanümerik olmayan karakter sayısı
    char *special_charset; // Özel karakter seti
    int dry_run; // Kuru çalıştırma
    int test_mode; // Test modu
    char *log_file; // Log dosyası
    char *log_level; // Log seviyesi
    int save_session; // Oturumu kaydet
    int session_timeout; // Oturum zaman aşımı
    int auto_pause; // Otomatik duraklatma
    int max_attempts; // Maksimum deneme sayısı
    int notify_on_completion; // Tamamlandığında bildirim
    int auto_save; // Otomatik kaydetme
    char *ban_ip; // Engellenmiş IP adresi
    char *whitelist_ip; // Beyaz listeye alınmış IP adresi
    int encrypt_output; // Çıktıyı şifrele
    int password_protect; // Şifre koruması
    int anonymize; // Anonimleştirme
    int secure_delete; // Güvenli silme
    int auto_backup; // Otomatik yedekleme
    char *backup_file; // Yedek dosyası
    char *restore_session; // Oturumu geri yükle
    int sms_notification; // SMS bildirimi
    int email_notification; // E-posta bildirimi
    char *proxy_address; // Proxy adresi
    char *proxy_chains; // Proxy zincirleri
    int timeout_value; // Zaman aşımı değeri
    int max_memory; // Maksimum bellek kullanımı
    int notify_on_error; // Hata durumunda bildirim
    char *error_log; // Hata logu
    char *session_file; // Oturum dosyası
    int enable_logging; // Loglamayı etkinleştir
    char *log_format; // Log formatı
    int dns_lookup; // DNS sorgusu
    int use_ssl; // SSL kullanımı
    char *http_proxy; // HTTP proxy
    char *socks_proxy; // SOCKS proxy
    char *no_proxy; // Proxy kullanılmayacak adresler
    int proxy_rotation; // Proxy döngüsü
    char *dynamic_charset; // Dinamik karakter seti
    int rate_limit; // Hız sınırlaması
    char *input_format; // Girdi formatı
    char *output_options; // Çıktı seçenekleri
    int max_retries; // Maksimum tekrar sayısı
    char *custom_rules; // Özel kurallar
    int hash_length; // Hash uzunluğu
    int session_restore_interval; // Oturum geri yükleme aralığı
    int debug_mode; // Hata ayıklama modu
    int show_stats; // İstatistikleri göster
    int enable_tuning; // Ayarları etkinleştir
    char *tuning_options; // Ayar seçenekleri
    int enable_failure_retry; // Hata durumunda tekrar denemeyi etkinleştir
    char *failure_retry_options; // Hata tekrar deneme seçenekleri
    char *custom_logging; // Özel loglama
} thread_data_t;

void hash_md5(const char *input, char *output) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)input, strlen(input), digest);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&output[i * 2], "%02x", digest[i]);
    }
}

void hash_sha1(const char *input, char *output) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)input, strlen(input), digest);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&output[i * 2], "%02x", digest[i]);
    }
}

void hash_sha256(const char *input, char *output) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&output[i * 2], "%02x", digest[i]);
    }
}

void hash_sha512(const char *input, char *output) {
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512((unsigned char *)input, strlen(input), digest);
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(&output[i * 2], "%02x", digest[i]);
    }
}

void *hash_crack(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    FILE *pass_file = fopen(data->password_list, "r");
    if (!pass_file) {
        perror("Parola dosyası açılamadı");
        return NULL;
    }

    char password[MAX_WORD_LEN];
    char computed_hash[MAX_WORD_LEN];

    while (fscanf(pass_file, "%s", password) != EOF) {
        switch (data->hash_type) {
            case HASH_MD5:
                hash_md5(password, computed_hash);
                break;
            case HASH_SHA1:
                hash_sha1(password, computed_hash);
                break;
            case HASH_SHA256:
                hash_sha256(password, computed_hash);
                break;
            case HASH_SHA512:
                hash_sha512(password, computed_hash);
                break;
            default:
                fprintf(stderr, "Bilinmeyen hash türü\n");
                fclose(pass_file);
                return NULL;
        }

        if (strcmp(computed_hash, data->hash) == 0) {
            if (data->verbose) {
                printf("Şifre bulundu: %s\n", password);
            }
            fclose(pass_file);
            return NULL;
        }
    }

    fclose(pass_file);
    return NULL;
}

void perform_http_request(const char *url, const char *post_data, const char *error_message, const char *otp_code, thread_data_t *data) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char msg[BUFFER_SIZE];

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        if (strcmp(data->method, "POST") == 0) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        }

        if (otp_code) {
            snprintf(msg, sizeof(msg), "OTP-Code: %s", otp_code);
            headers = curl_slist_append(headers, msg);
        }

        if (data->proxy) {
            curl_easy_setopt(curl, CURLOPT_PROXY, data->proxy);
        }

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, data->timeout);
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "HTTP isteği başarısız: %s\n", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}

int main(int argc, char *argv[]) {
    thread_data_t data;

    // Varsayılan değerler
    data.target_ip = NULL;
    data.username_list = NULL;
    data.password_list = NULL;
    data.attack_type = NULL;
    data.form_info = NULL;
    data.error_message = NULL;
    data.hash = NULL;
    data.hash_type = HASH_UNKNOWN;
    data.verbose = 0;
    data.method = NULL;
    data.form_fields = NULL;
    data.otp_codes_file = NULL;
    data.proxy = NULL;
    data.timeout = 5;

    // Yeni parametreleri varsayılan değerlere ayarla
    data.input_file = NULL;
    data.output_file = NULL;
    data.output_format = NULL;
    data.single_hash = 0;
    data.batch_mode = 0;
    data.interactive_mode = 0;
    data.silent_mode = 0;
    data.verbose_mode = 0;
    data.progress_bar = 0;
    data.brute_force = 0;
    data.dictionary = NULL;
    data.wordlist = NULL;
    data.min_length = 0;
    data.max_length = 0;
    data.charset = NULL;
    data.incremental = 0;
    data.mask = NULL;
    data.attack_mode = NULL;
    data.threads = 1;
    data.gpu = 0;
    data.priority = 0;
    data.memory_limit = NULL;
    data.skip_errors = 0;
    data.retry = 0;
    data.rules = NULL;
    data.exclude_chars = NULL;
    data.include_chars = NULL;
    data.min_numbers = 0;
    data.min_uppercase = 0;
    data.min_lowercase = 0;
    data.max_non_alpha = 0;
    data.special_charset = NULL;
    data.dry_run = 0;
    data.test_mode = 0;
    data.log_file = NULL;
    data.log_level = NULL;
    data.save_session = 0;
    data.session_timeout = 0;
    data.auto_pause = 0;
    data.max_attempts = 0;
    data.notify_on_completion = 0;
    data.auto_save = 0;
    data.ban_ip = NULL;
    data.whitelist_ip = NULL;
    data.encrypt_output = 0;
    data.password_protect = 0;
    data.anonymize = 0;
    data.secure_delete = 0;
    data.auto_backup = 0;
    data.backup_file = NULL;
    data.restore_session = NULL;
    data.sms_notification = 0;
    data.email_notification = 0;
    data.proxy_address = NULL;
    data.proxy_chains = NULL;
    data.timeout_value = 0;
    data.max_memory = 0;
    data.notify_on_error = 0;
    data.error_log = NULL;
    data.session_file = NULL;
    data.enable_logging = 0;
    data.log_format = NULL;
    data.dns_lookup = 0;
    data.use_ssl = 0;
    data.http_proxy = NULL;
    data.socks_proxy = NULL;
    data.no_proxy = NULL;
    data.proxy_rotation = 0;
    data.dynamic_charset = NULL;
    data.rate_limit = 0;
    data.input_format = NULL;
    data.output_options = NULL;
    data.max_retries = 0;
    data.custom_rules = NULL;
    data.hash_length = 0;
    data.session_restore_interval = 0;
    data.debug_mode = 0;
    data.show_stats = 0;
    data.enable_tuning = 0;
    data.tuning_options = NULL;
    data.enable_failure_retry = 0;
    data.failure_retry_options = NULL;
    data.custom_logging = NULL;

    // Komut satırı argümanlarını işleme
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            data.target_ip = argv[++i];
        } else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            data.username_list = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            data.password_list = argv[++i];
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            data.error_message = argv[++i];
        } else if (strcmp(argv[i], "-H") == 0 && i + 1 < argc) {
            data.hash = argv[++i];
            if (strstr(data.hash, "$1$")) {
                data.hash_type = HASH_MD5;
            } else if (strstr(data.hash, "$2a$") || strstr(data.hash, "$2b$") || strstr(data.hash, "$2y$")) {
                data.hash_type = HASH_SHA256;
            } else if (strstr(data.hash, "$6$")) {
                data.hash_type = HASH_SHA512;
            } else {
                data.hash_type = HASH_UNKNOWN;
            }
        } else if (strcmp(argv[i], "-v") == 0) {
            data.verbose = 1;
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            data.method = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            data.form_fields = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            data.output_file = argv[++i];
        } else if (strcmp(argv[i], "--input-file") == 0 && i + 1 < argc) {
            data.input_file = argv[++i];
        } else if (strcmp(argv[i], "--output-format") == 0 && i + 1 < argc) {
            data.output_format = argv[++i];
        } else if (strcmp(argv[i], "--single-hash") == 0) {
            data.single_hash = 1;
        } else if (strcmp(argv[i], "--batch-mode") == 0) {
            data.batch_mode = 1;
        } else if (strcmp(argv[i], "--interactive-mode") == 0) {
            data.interactive_mode = 1;
        } else if (strcmp(argv[i], "--silent-mode") == 0) {
            data.silent_mode = 1;
        } else if (strcmp(argv[i], "--verbose-mode") == 0) {
            data.verbose_mode = 1;
        } else if (strcmp(argv[i], "--progress-bar") == 0) {
            data.progress_bar = 1;
        } else if (strcmp(argv[i], "--brute-force") == 0) {
            data.brute_force = 1;
        } else if (strcmp(argv[i], "--dictionary") == 0 && i + 1 < argc) {
            data.dictionary = argv[++i];
        } else if (strcmp(argv[i], "--wordlist") == 0 && i + 1 < argc) {
            data.wordlist = argv[++i];
        } else if (strcmp(argv[i], "--min-length") == 0 && i + 1 < argc) {
            data.min_length = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-length") == 0 && i + 1 < argc) {
            data.max_length = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--charset") == 0 && i + 1 < argc) {
            data.charset = argv[++i];
        } else if (strcmp(argv[i], "--incremental") == 0) {
            data.incremental = 1;
        } else if (strcmp(argv[i], "--mask") == 0 && i + 1 < argc) {
            data.mask = argv[++i];
        } else if (strcmp(argv[i], "--attack-mode") == 0 && i + 1 < argc) {
            data.attack_mode = argv[++i];
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            data.threads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--gpu") == 0) {
            data.gpu = 1;
        } else if (strcmp(argv[i], "--priority") == 0 && i + 1 < argc) {
            data.priority = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--memory-limit") == 0 && i + 1 < argc) {
            data.memory_limit = argv[++i];
        } else if (strcmp(argv[i], "--skip-errors") == 0) {
            data.skip_errors = 1;
        } else if (strcmp(argv[i], "--retry") == 0 && i + 1 < argc) {
            data.retry = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--rules") == 0 && i + 1 < argc) {
            data.rules = argv[++i];
        } else if (strcmp(argv[i], "--exclude-chars") == 0 && i + 1 < argc) {
            data.exclude_chars = argv[++i];
        } else if (strcmp(argv[i], "--include-chars") == 0 && i + 1 < argc) {
            data.include_chars = argv[++i];
        } else if (strcmp(argv[i], "--min-numbers") == 0 && i + 1 < argc) {
            data.min_numbers = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--min-uppercase") == 0 && i + 1 < argc) {
            data.min_uppercase = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--min-lowercase") == 0 && i + 1 < argc) {
            data.min_lowercase = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-non-alpha") == 0 && i + 1 < argc) {
            data.max_non_alpha = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--special-charset") == 0 && i + 1 < argc) {
            data.special_charset = argv[++i];
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            data.dry_run = 1;
        } else if (strcmp(argv[i], "--test-mode") == 0) {
            data.test_mode = 1;
        } else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc) {
            data.log_file = argv[++i];
        } else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
            data.log_level = argv[++i];
        } else if (strcmp(argv[i], "--save-session") == 0) {
            data.save_session = 1;
        } else if (strcmp(argv[i], "--session-timeout") == 0 && i + 1 < argc) {
            data.session_timeout = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--auto-pause") == 0) {
            data.auto_pause = 1;
        } else if (strcmp(argv[i], "--max-attempts") == 0 && i + 1 < argc) {
            data.max_attempts = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--notify-on-completion") == 0) {
            data.notify_on_completion = 1;
        } else if (strcmp(argv[i], "--auto-save") == 0) {
            data.auto_save = 1;
        } else if (strcmp(argv[i], "--ban-ip") == 0 && i + 1 < argc) {
            data.ban_ip = argv[++i];
        } else if (strcmp(argv[i], "--whitelist-ip") == 0 && i + 1 < argc) {
            data.whitelist_ip = argv[++i];
        } else if (strcmp(argv[i], "--encrypt-output") == 0) {
            data.encrypt_output = 1;
        } else if (strcmp(argv[i], "--password-protect") == 0) {
            data.password_protect = 1;
        } else if (strcmp(argv[i], "--anonymize") == 0) {
            data.anonymize = 1;
        } else if (strcmp(argv[i], "--secure-delete") == 0) {
            data.secure_delete = 1;
        } else if (strcmp(argv[i], "--auto-backup") == 0) {
            data.auto_backup = 1;
        } else if (strcmp(argv[i], "--backup-file") == 0 && i + 1 < argc) {
            data.backup_file = argv[++i];
        } else if (strcmp(argv[i], "--restore-session") == 0 && i + 1 < argc) {
            data.restore_session = argv[++i];
        } else if (strcmp(argv[i], "--sms-notification") == 0) {
            data.sms_notification = 1;
        } else if (strcmp(argv[i], "--email-notification") == 0) {
            data.email_notification = 1;
        } else if (strcmp(argv[i], "--proxy-address") == 0 && i + 1 < argc) {
            data.proxy_address = argv[++i];
        } else if (strcmp(argv[i], "--proxy-chains") == 0 && i + 1 < argc) {
            data.proxy_chains = argv[++i];
        } else if (strcmp(argv[i], "--timeout-value") == 0 && i + 1 < argc) {
            data.timeout_value = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-memory") == 0 && i + 1 < argc) {
            data.max_memory = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--notify-on-error") == 0) {
            data.notify_on_error = 1;
        } else if (strcmp(argv[i], "--error-log") == 0 && i + 1 < argc) {
            data.error_log = argv[++i];
        } else if (strcmp(argv[i], "--session-file") == 0 && i + 1 < argc) {
            data.session_file = argv[++i];
        } else if (strcmp(argv[i], "--enable-logging") == 0) {
            data.enable_logging = 1;
        } else if (strcmp(argv[i], "--log-format") == 0 && i + 1 < argc) {
            data.log_format = argv[++i];
        } else if (strcmp(argv[i], "--dns-lookup") == 0) {
            data.dns_lookup = 1;
        } else if (strcmp(argv[i], "--use-ssl") == 0) {
            data.use_ssl = 1;
        } else if (strcmp(argv[i], "--http-proxy") == 0 && i + 1 < argc) {
            data.http_proxy = argv[++i];
        } else if (strcmp(argv[i], "--socks-proxy") == 0 && i + 1 < argc) {
            data.socks_proxy = argv[++i];
        } else if (strcmp(argv[i], "--no-proxy") == 0 && i + 1 < argc) {
            data.no_proxy = argv[++i];
        } else if (strcmp(argv[i], "--proxy-rotation") == 0) {
            data.proxy_rotation = 1;
        } else if (strcmp(argv[i], "--dynamic-charset") == 0 && i + 1 < argc) {
            data.dynamic_charset = argv[++i];
        } else if (strcmp(argv[i], "--rate-limit") == 0 && i + 1 < argc) {
            data.rate_limit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--input-format") == 0 && i + 1 < argc) {
            data.input_format = argv[++i];
        } else if (strcmp(argv[i], "--output-options") == 0 && i + 1 < argc) {
            data.output_options = argv[++i];
        } else if (strcmp(argv[i], "--max-retries") == 0 && i + 1 < argc) {
            data.max_retries = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--custom-rules") == 0 && i + 1 < argc) {
            data.custom_rules = argv[++i];
        } else if (strcmp(argv[i], "--hash-length") == 0 && i + 1 < argc) {
            data.hash_length = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--session-restore-interval") == 0 && i + 1 < argc) {
            data.session_restore_interval = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--debug-mode") == 0) {
            data.debug_mode = 1;
        } else if (strcmp(argv[i], "--show-stats") == 0) {
            data.show_stats = 1;
        } else if (strcmp(argv[i], "--enable-tuning") == 0) {
            data.enable_tuning = 1;
        } else if (strcmp(argv[i], "--tuning-options") == 0 && i + 1 < argc) {
            data.tuning_options = argv[++i];
        } else if (strcmp(argv[i], "--enable-failure-retry") == 0) {
            data.enable_failure_retry = 1;
        } else if (strcmp(argv[i], "--failure-retry-options") == 0 && i + 1 < argc) {
            data.failure_retry_options = argv[++i];
        } else if (strcmp(argv[i], "--custom-logging") == 0 && i + 1 < argc) {
            data.custom_logging = argv[++i];
        }
    }

    // İşlem yapılacak yer
    if (data.verbose) {
        printf("Hedef IP: %s\n", data.target_ip);
        printf("Kullanıcı adı: %s\n", data.username);
        printf("Şifre: %s\n", data.password);
        // Diğer parametreleri yazdır
    }

    // İşlemleri gerçekleştirme kısmı
    if (data.dry_run) {
        printf("Kuru çalıştırma modu etkin. Gerçek işlemler yapılmayacak.\n");
    } else {
        // Gerçek işlemleri burada gerçekleştir
    }

    return 0;
}
