#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {

        // Разбор командной строки
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        // Контекст
        CryptoGuard::CryptoGuardCtx cryptoCtx;

        auto open_file = [](std::fstream &ff, const char *name, const char *msg, bool in = true) {
            ff.open(name, in ? std::ios_base::in : std::ios_base::out);
            if (!ff.is_open())
                throw std::runtime_error{msg};
        };

        // Действие по команде
        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream fi, fo;
            open_file(fi, options.GetInputFile().c_str(), "Error opening input file");
            open_file(fo, options.GetOutputFile().c_str(), "Error opening output file", false);

            cryptoCtx.EncryptFile(fi, fo, options.GetPassword());

            fi.close();
            fo.close();

            std::print("File encoded successfully\n");
        } break;

        case COMMAND_TYPE::DECRYPT: {
            std::fstream fi, fo;
            open_file(fi, options.GetInputFile().c_str(), "Error opening input file");
            open_file(fo, options.GetOutputFile().c_str(), "Error opening output file", false);

            cryptoCtx.DecryptFile(fi, fo, options.GetPassword());

            fi.close();
            fo.close();

            std::print("File decoded successfully\n");
        } break;

        case COMMAND_TYPE::CHECKSUM: {
            std::fstream fi;
            open_file(fi, options.GetInputFile().c_str(), "Error opening input file");

            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(fi));

            fi.close();
        } break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
