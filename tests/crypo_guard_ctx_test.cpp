#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <ios>
#include <istream>
#include <stdexcept>
#include <string_view>

using namespace CryptoGuard;

// шифровать
void encrypt(std::iostream &in, std::iostream &out, std::string_view password) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    cryptoCtx.EncryptFile(in, out, password);
}

// дешифровать
void decrypt(std::iostream &in, std::iostream &out, std::string_view password) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    cryptoCtx.DecryptFile(in, out, password);
}

// пустой вход
void emptyIn(bool encr) {
    std::stringstream in, out;
    std::string_view pswd("12341234");
    if (encr)
        encrypt(in, out, pswd);
    else
        decrypt(in, out, pswd);

    EXPECT_EQ(in.str(), out.str());
    EXPECT_EQ(in.str(), "");
}

// непустой вход
void notEmptyIn() {
    std::stringstream en_in("1234"), en_out;
    std::string_view pswd("12341234");
    encrypt(en_in, en_out, pswd);

    std::stringstream de_in(en_out.str()), de_out;
    decrypt(de_in, de_out, pswd);

    EXPECT_EQ(en_out.str().empty(), false);
    EXPECT_EQ(en_in.str(), de_out.str());
}

void badbit(bool encr, bool in) {
    std::stringstream in_str, out_str;
    std::string_view pswd("12341234");
    if (in)
        in_str.setstate(std::ios_base::badbit);
    else
        out_str.setstate(std::ios_base::badbit);
    ASSERT_THROW(encr ? encrypt(in_str, out_str, pswd) : decrypt(in_str, out_str, pswd), std::runtime_error);
}

// Encrypt test 1 пустой вход
TEST(EncryptFile, EmptyIn) { emptyIn(true); }

// Encrypt test 2 непустой вход
TEST(EncryptFile, NotEmptyIn) { notEmptyIn(); }

// Encrypt test 3 ошибка состояния входа
TEST(EncryptFile, BadIn) { badbit(true, true); }

// Encrypt test 4 ошибка состояния выхода
TEST(EncryptFile, BadOut) { badbit(true, false); }

// Decrypt test 1 пустой вход
TEST(DecryptFile, EmptyIn) { emptyIn(false); }

// Decrypt test 2 непустой вход
TEST(DecryptFile, NotEmptyIn) { notEmptyIn(); }

// Decrypt test 3 ошибка состояния входа
TEST(DecryptFile, BadIn) { badbit(false, true); }

// Decrypt test 4 ошибка состояния выхода
TEST(DecryptFile, BadOut) { badbit(false, false); }

// CalculateChecksum test 1 ошибка состояния входа
TEST(CalculateChecksum, BadIn) {
    std::stringstream in;
    in.setstate(std::ios_base::badbit);
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    ASSERT_THROW(cryptoCtx.CalculateChecksum(in), std::runtime_error);
}

// CalculateChecksum test 2 пустой вход, сравнение с эталоном
TEST(CalculateChecksum, EmptyIn) {
    std::stringstream in;
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    // Эталон - контрольная сумма SHA-256 от пустого сообщения (строки нулевой длины)
    EXPECT_EQ(cryptoCtx.CalculateChecksum(in), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

// CalculateChecksum test 3 непустой вход, сравнение с эталоном
TEST(CalculateChecksum, NotEmptyIn) {
    std::stringstream in("Test Message\nHello World\n");
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    // Эталон - контрольная сумма, полученная для исходных текстов и сообщения из примера в задании
    EXPECT_EQ(cryptoCtx.CalculateChecksum(in), "318b20b83a6730b928c46163a2a1cefee4466132731c95c39613acb547ccb715");
}

// CalculateChecksum test 4 сравнение сумм до шифрования/дешифрования и после
TEST(CalculateChecksum, EqualSums) {
    std::string_view msg = "Test Message\nHello World\n", pswd = "12341234";

    std::stringstream in(msg.data()), en_in(msg.data()), en_out;
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    // Сумма до шифрования/дефшифрования
    std::string sum_before(cryptoCtx.CalculateChecksum(in));

    cryptoCtx.EncryptFile(en_in, en_out, pswd);

    std::stringstream de_in(en_out.str()), de_out;
    cryptoCtx.DecryptFile(de_in, de_out, pswd);

    // Сравнение
    EXPECT_EQ(sum_before, cryptoCtx.CalculateChecksum(de_out));
}
