#include "cmd_options.h"
#include <gtest/gtest.h>
#include <string_view>

using namespace CryptoGuard;

// Проверка соответствия значений po аргументам командной строки
void CheckOptionsState(const ProgramOptions &po,
                       ProgramOptions::COMMAND_TYPE cmd = ProgramOptions::COMMAND_TYPE::UNKNOWN,
                       std::string_view inFile = "", std::string_view outFile = "", std::string_view password = "") {
    EXPECT_EQ(po.GetCommand(), cmd);
    EXPECT_EQ(po.GetInputFile(), inFile);
    EXPECT_EQ(po.GetOutputFile(), outFile);
    EXPECT_EQ(po.GetPassword(), password);
}

// 1 Пустая командная строка
TEST(ProgramOptions, EmptyArgString) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./CryptoGuard"};
    try {
        po.Parse(sizeof(argv) / sizeof(argv[0]), (char **)argv);  // C-style, staic_cast не справляется..
    } catch (...) {
        CheckOptionsState(po);
    }
}

// 2 Команда Help
TEST(ProgramOptions, Help) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./CryptoGuard", "--help"};

    po.Parse(sizeof(argv) / sizeof(argv[0]), (char **)argv);

    CheckOptionsState(po);
}

// 3 Команда Encrypt с полным списком своих аргументов
TEST(ProgramOptions, Encrypt) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./CryptoGuard", "--command", "encrypt",    "--input", "in",
                          "--output",      "out",       "--password", "pswd"};

    po.Parse(sizeof(argv) / sizeof(argv[0]), (char **)argv);

    CheckOptionsState(po, ProgramOptions::COMMAND_TYPE::ENCRYPT, "in", "out", "pswd");
}

// 4 Команда Decrypt с полным списком своих аргументов
TEST(ProgramOptions, Decrypt) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./CryptoGuard", "--command", "decrypt",    "--input", "in",
                          "--output",      "out",       "--password", "pswd"};

    po.Parse(sizeof(argv) / sizeof(argv[0]), (char **)argv);

    CheckOptionsState(po, ProgramOptions::COMMAND_TYPE::DECRYPT, "in", "out", "pswd");
}

// 5 Команда Checksum с полным списком своих аргументов
TEST(ProgramOptions, Checksum) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./CryptoGuard", "--command", "checksum", "--input", "in"};
    po.Parse(sizeof(argv) / sizeof(argv[0]), (char **)argv);

    CheckOptionsState(po, ProgramOptions::COMMAND_TYPE::CHECKSUM, "in");
}

// 6 Команда Encrypt без указания входного файла
TEST(ProgramOptions, EncryptNoInput) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./CryptoGuard", "--command", "encrypt"};

    try {
        po.Parse(sizeof(argv) / sizeof(argv[0]), (char **)argv);
    } catch (...) {
        CheckOptionsState(po, ProgramOptions::COMMAND_TYPE::ENCRYPT);
    }
}

// 7 Команда Encrypt без указания выходного файла
TEST(ProgramOptions, EncryptNoOutput) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./CryptoGuard", "--command", "encrypt", "--input", "in"};

    try {
        po.Parse(sizeof(argv) / sizeof(argv[0]), (char **)argv);
    } catch (...) {
        CheckOptionsState(po, ProgramOptions::COMMAND_TYPE::ENCRYPT, "in");
    }
}

// 8 Команда Encrypt без указания пароля
TEST(ProgramOptions, EncryptNoPassword) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./CryptoGuard", "--command", "encrypt", "--input", "in", "--output", "out"};

    try {
        po.Parse(sizeof(argv) / sizeof(argv[0]), (char **)argv);
    } catch (...) {
        CheckOptionsState(po, ProgramOptions::COMMAND_TYPE::ENCRYPT, "in", "out");
    }
}
