#!/bin/bash

# setup.sh - Gerekli araçları ve kütüphaneleri kurar

# Kendi betiğinizi tanımlayın
set -e

# Fonksiyonlar
function print_info {
    echo "INFO: $1"
}

function print_error {
    echo "ERROR: $1" >&2
}

function install_package {
    local package=$1
    if dpkg -l | grep -q "^ii  $package "; then
        print_info "$package zaten kurulu."
    else
        print_info "$package kuruluyor..."
        sudo apt-get install -y "$package"
        if [ $? -ne 0 ]; then
            print_error "$package kurulurken bir hata oluştu."
            exit 1
        fi
    fi
}

function update_system {
    print_info "Sistem güncelleniyor..."
    sudo apt-get update
    if [ $? -ne 0 ]; then
        print_error "Sistem güncelleme sırasında bir hata oluştu."
        exit 1
    fi
}

# Ana işlem
print_info "Kurulum başlatılıyor..."

# Güncellemeleri yap
update_system

# Gereken paketleri kur
install_package "gcc"
install_package "libc6-dev"
install_package "build-essential"  # Genel geliştirme araçları
install_package "make"              # Make aracı (derleme için)

print_info "Kurulum tamamlandı!"

# Bilgilendirme
print_info "Lütfen 'gcc', 'make' ve diğer geliştirme araçlarını kullanarak projelerinizi derlemeye devam edin."
