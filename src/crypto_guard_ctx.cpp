#include "crypto_guard_ctx.h"
#include <array>
#include <iomanip>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <string.h>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
    AesCipherParams CreateCiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (!result) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    void EnDecrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password, int decrypt = 0);

public:
    Impl() {}
    ~Impl() {}

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);
};

// Шифровать/дешифровать
void CryptoGuardCtx::Impl::EnDecrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                                     int decrypt) {
    // Проверка состояния потоков..
    if (!inStream)
        throw std::runtime_error{decrypt ? "!inStream while decrypting" : "!inStream while encrypting"};
    if (!outStream)
        throw std::runtime_error{decrypt ? "!outStream while decrypting" : "!outStream while encrypting"};

    using ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

    auto print_err = []() {
        auto err = ERR_get_error();
        if (err)
            throw std::runtime_error{ERR_error_string(err, nullptr)};
    };

    auto params = CreateCiperParamsFromPassword(password);
    params.encrypt = !decrypt;

    // Создание контекста.
    ctx_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx.get())
        print_err();

    // Инициализация контекста.
    if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt))
        print_err();

    const short bufSz = 1024;
    std::array<unsigned char, bufSz> inbuf;
    std::array<unsigned char, bufSz + EVP_MAX_BLOCK_LENGTH> outbuf;
    int inlen = 0, outlen = 0, total = 0 /*общее число прочитанных байт*/;

    // Обновление данными ввода.
    for (;;) {
        inStream.read(reinterpret_cast<char *>(inbuf.data()), bufSz);
        inlen = inStream.gcount();
        if (inlen) {
            if (!EVP_CipherUpdate(ctx.get(), outbuf.data(), &outlen, inbuf.data(), inlen))
                print_err();
            outStream.write(reinterpret_cast<char *>(outbuf.data()), outlen);
            if (outStream.bad())
                throw std::runtime_error{decrypt ? "outStream.bad() while decrypting"
                                                 : "outStream.bad() while encrypting"};
            total += inlen;
        }

        // проблема
        if (inStream.bad())
            throw std::runtime_error{decrypt ? "inStream.bad() while decrypting" : "inStream.bad() while encrypting"};
        // конец файла
        else if (inStream.eof())
            break;
    }

    // Формирование результата.
    if (total) {
        if (!EVP_CipherFinal_ex(ctx.get(), outbuf.data(), &outlen))
            print_err();
        outStream.write((char *)outbuf.data(), outlen);
    }
}

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    EnDecrypt(inStream, outStream, password);
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    EnDecrypt(inStream, outStream, password, 1);
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) {

    using ctx_ptr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

    // Проверка состояния потока..
    if (!inStream)
        throw std::runtime_error{"!inStream while calculating checksum"};

    const short bufSz = 1024;
    std::array<unsigned char, bufSz> inbuf;
    std::array<unsigned char, EVP_MAX_MD_SIZE> md_value;
    unsigned md_len;

    auto print_err = []() {
        auto err = ERR_get_error();
        if (err)
            throw std::runtime_error{ERR_error_string(err, nullptr)};
    };

    // Создание контекста.
    ctx_ptr mdctx(EVP_MD_CTX_new());
    if (!mdctx.get())
        print_err();

    // Инициализация контекста.
    if (!EVP_DigestInit_ex2(mdctx.get(), EVP_sha256(), nullptr))
        print_err();

    // Обновление данными ввода.
    for (;;) {
        inStream.read(reinterpret_cast<char *>(inbuf.data()), bufSz);
        if (int inlen = inStream.gcount())
            if (!EVP_DigestUpdate(mdctx.get(), inbuf.data(), inlen))
                print_err();
        // проблема
        if (inStream.bad())
            throw std::runtime_error{"inStream.bad() while calculating checksum"};
        // конец файла
        else if (inStream.eof())
            break;
    }

    // Формирование результата.
    if (!EVP_DigestFinal_ex(mdctx.get(), md_value.data(), &md_len))
        print_err();

    std::stringstream ret;
    for (size_t i = 0; i < md_len; ++i)
        ret << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md_value[i]);

    return ret.str();
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
