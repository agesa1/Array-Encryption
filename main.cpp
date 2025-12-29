#include <iostream>
#include <vector>
#include <iomanip>
#include "arrayenc.h"

int main() {
    std::vector<int> original = { 42, 128, 255, 1024, 999, 2048, 4096 };

    std::cout << "original: ";
    for (size_t i = 0; i < original.size(); i++) {
        std::cout << original[i];
        if (i < original.size() - 1) std::cout << " ";
    }
    std::cout << std::endl;

    ArrayEncryption enc;
    std::vector<uint8_t> encrypted = enc.encrypt(original);

    std::cout << "encrypted: ";
    for (size_t i = 0; i < encrypted.size(); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(encrypted[i]);
        if (i < encrypted.size() - 1) std::cout << " ";
    }
    std::cout << std::dec << std::endl;

    std::vector<int> decrypted = enc.decrypt(encrypted);

    std::cout << "decrypted: ";
    for (size_t i = 0; i < decrypted.size(); i++) {
        std::cout << decrypted[i];
        if (i < decrypted.size() - 1) std::cout << " ";
    }
    std::cout << std::endl;

    bool match = (original == decrypted);
    std::cout << "status: " << (match ? "pass" : "fail") << std::endl;

    return match ? 0 : 1;
}
