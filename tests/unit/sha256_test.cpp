#include <algorithm>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

#include "ost2pst/util/sha256.h"

#include "test_support.h"

namespace {
using ost2pst::util::ByteView;
using ost2pst::util::Sha256;
using ost2pst::util::sha256_hex;

ByteView view(const std::string& text) {
    return ByteView(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

void check_standard_vectors() {
    const std::pair<std::string, std::string> vectors[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {std::string(1000000, 'a'),
         "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
    };
    for (const auto& [text, expected] : vectors) {
        Sha256 hash;
        TEST_OK(hash.update(view(text)), "standard SHA-256 vector");
        TEST_CHECK(sha256_hex(hash.digest()) == expected);
        TEST_CHECK(sha256_hex(hash.digest()) == expected);
        TEST_EQ(hash.size(), text.size(), "digest does not pad the original state");
    }
}

void check_padding_and_chunk_boundaries() {
    // Independent expected hashes generated with Python hashlib for bytes(i % 251).
    const std::pair<size_t, const char*> vectors[] = {
        {55, "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59"},
        {56, "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562"},
        {63, "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488"},
        {64, "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108"},
        {65, "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781"},
        {127, "92ca0fa6651ee2f97b884b7246a562fa71250fedefe5ebf270d31c546bfea976"},
        {128, "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5"},
        {129, "5099c6a56203f9687f7d33f4bfdf576d31dc91f6b695ecea38b2770c87631135"},
    };
    for (const auto& [size, expected] : vectors) {
        std::vector<uint8_t> bytes(size);
        for (size_t i = 0; i < size; ++i)
            bytes[i] = static_cast<uint8_t>(i % 251);
        for (size_t split = 0; split <= size; ++split) {
            Sha256 hash;
            TEST_OK(hash.update(ByteView(bytes.data(), split)), "prefix");
            const auto snapshot = hash.digest();
            TEST_CHECK(snapshot == hash.digest());
            TEST_OK(hash.update(ByteView()), "empty update in partial block");
            TEST_OK(hash.update(ByteView(bytes.data() + split, size - split)), "suffix");
            TEST_CHECK(sha256_hex(hash.digest()) == expected);
        }
        Sha256 bytewise;
        for (uint8_t byte : bytes)
            TEST_OK(bytewise.update(ByteView(&byte, 1)), "single byte");
        TEST_CHECK(sha256_hex(bytewise.digest()) == expected);
    }
}

void check_rejected_updates_leave_state_intact() {
    Sha256 hash;
    TEST_OK(hash.update(view("abc")), "valid prefix");
    const auto before = hash.digest();
    auto invalid = hash.update(ByteView(nullptr, 1));
    TEST_ERROR(invalid, ost2pst::util::ErrorKind::kBadField, "SHA256.data", "null input");
    if constexpr (sizeof(size_t) >= sizeof(uint64_t)) {
        auto overflow = hash.update(ByteView(nullptr, std::numeric_limits<size_t>::max()));
        TEST_ERROR(overflow, ost2pst::util::ErrorKind::kBadField, "SHA256.length",
                   "length overflow");
    }
    TEST_EQ(hash.size(), 3u, "rejected input not counted");
    TEST_CHECK(hash.digest() == before);
    TEST_OK(hash.update(view("dbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")), "continue");
    TEST_CHECK(sha256_hex(hash.digest()) ==
               "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

void check_file_streaming() {
    const auto path = std::filesystem::temp_directory_path() / "ost2pst_sha256_test.bin";
    std::vector<uint8_t> bytes(1048593);
    for (size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<uint8_t>(i % 251);
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
        TEST_CHECK(output.good());
    }
    {
        auto opened = ost2pst::util::FileReader::open(path.wstring());
        TEST_OK(opened, "open hash fixture");
        if (opened.ok()) {
            auto digest = ost2pst::util::sha256_file(opened.value());
            TEST_OK(digest, "hash file across 1 MiB read boundary");
            if (digest.ok())
                TEST_CHECK(sha256_hex(digest.value()) ==
                           "f4bf9b8dec6e3e28b2ec33266145d244fe97a6bce1ec054ace053bab67d2ef9a");
        }
    }
    std::error_code error;
    std::filesystem::remove(path, error);
    TEST_CHECK(!error);

    // The reader caches its opening size: a later short read must propagate, not return a
    // successful digest of a prefix. Stable-handle protection is tested by the I/O layer.
    {
        std::ofstream output(path, std::ios::binary);
        output << "abc";
    }
    {
        auto opened = ost2pst::util::FileReader::open(path.wstring());
        TEST_OK(opened, "open before truncation");
        if (opened.ok()) {
            {
                std::ofstream truncated(path, std::ios::binary | std::ios::trunc);
            }
            auto digest = ost2pst::util::sha256_file(opened.value());
            TEST_ERROR(digest, ost2pst::util::ErrorKind::kIo, "FileReader.read",
                       "short read is not a fingerprint");
        }
    }
    {
        auto opened = ost2pst::util::FileReader::open(path.wstring());
        TEST_OK(opened, "open empty file");
        if (opened.ok()) {
            auto digest = ost2pst::util::sha256_file(opened.value());
            TEST_OK(digest, "hash empty file");
            if (digest.ok())
                TEST_CHECK(sha256_hex(digest.value()) ==
                           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        }
    }
    std::filesystem::remove(path, error);
    TEST_CHECK(!error);
    ost2pst::util::FileReader closed;
    auto missing = ost2pst::util::sha256_file(closed);
    TEST_ERROR(missing, ost2pst::util::ErrorKind::kIo, "SHA256.file", "closed input");
}
} // namespace

int main() {
    check_standard_vectors();
    check_padding_and_chunk_boundaries();
    check_rejected_updates_leave_state_intact();
    check_file_streaming();
    return ost2pst::test::finish("sha256_test");
}
