#include "cmd_options.h"
#include <iostream>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    /*
        help — список доступных опций;
        command — команда encrypt, decrypt или checksum;
        input — путь до входного файла;
        output — путь до файла, в котором будет сохранён результат;
        password — пароль для шифрования и дешифрования.
    */
    desc_.add_options()
        // Опция --help - список доступных опций
        ("help,h", "show help")
        // Опция --command cmnd — команда encrypt, decrypt или checksum -> command_
        ("command,c", po::value(&_command_)->value_name("cmnd"), "encrypt, decrypt or checksum")
        // Опция --input file — путь до входного файла -> inputFile_
        ("input,i", po::value(&inputFile_)->value_name("file"), "input file name")
        // Опция --output file — путь до файла, в котором будет сохранён результат -> outputFile_
        ("output,o", po::value(&outputFile_)->value_name("file"), "output file name")
        // Опция --password pswd — пароль для шифрования и дешифрования
        ("password,p", po::value(&password_)->value_name("pswd"), "encrypt/decrypt password");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    const auto cit = commandMapping_.find(_command_);
    command_ = cit != commandMapping_.cend() ? cit->second : COMMAND_TYPE::UNKNOWN;

    if (vm.contains("help")) {
        // Если был указан параметр --help, то выводим справку
        std::cout << desc_;
        return;
    }

    // Проверяем наличие остальных опций
    if (!vm.contains("command")) {
        throw std::runtime_error("Command option is missing, type --help for help");
    }

    if (command_ == COMMAND_TYPE::CHECKSUM)
        if (!vm.contains("input"))
            throw std::runtime_error("Input file is not specified");

    if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
        if (!vm.contains("input"))
            throw std::runtime_error("Input file is not specified");
        if (!vm.contains("output"))
            throw std::runtime_error("Output file is not specified");
        if (!vm.contains("password"))
            throw std::runtime_error("Password is not specified");
    }
}

}  // namespace CryptoGuard
