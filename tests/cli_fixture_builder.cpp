// Generated synthetic corpus only; no mailbox bytes are committed.
#include <cstdio>
#include <filesystem>
#include <fstream>

#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/msg/mailbox.h"
#include "ost2pst/writer/content.h"

int wmain(int argc, wchar_t** argv) {
    if (argc != 2 && argc != 4)
        return 1;
    const bool corrupt = argc == 4 && std::wstring(argv[2]) == L"--incomplete";
    const bool complete = argc == 4 && (std::wstring(argv[2]) == L"--complete" || corrupt);
    if (argc == 4 && !complete)
        return 1;
    const int count = complete ? _wtoi(argv[3]) : 1;
    if (count < 1 || count > 2000)
        return 1;
    namespace writer = ost2pst::writer;
    writer::StoreRequest request;
    request.named_properties.push_back({u"M7SyntheticProperty"});
    writer::ContentFolder folder;
    folder.name = u"M7 synthetic corpus";
    folder.parent_nid = writer::kNidIpmsubtree;
    writer::ContentMessage message;
    const auto text = [](const std::u16string& s) {
        std::vector<uint8_t> v;
        for (auto c : s) {
            v.push_back(static_cast<uint8_t>(c));
            v.push_back(static_cast<uint8_t>(c >> 8));
        }
        return v;
    };
    if (complete) {
        message.properties = {{0x001A, 0x001F, text(u"IPM.Note")},
                              {0x0E07, 0x0003, {1, 0, 0, 0}},
                              {0x0E08, 0x0003, {0, 0, 2, 0}},
                              {0x0E17, 0x0003, {0, 0, 0, 0}},
                              {0x3007, 0x0040, std::vector<uint8_t>(8, 0x30)},
                              {0x3008, 0x0040, std::vector<uint8_t>(8, 0x31)},
                              {0x300B, 0x0102, std::vector<uint8_t>(16, 0x40)},
                              {0x0037, 0x001F, text(u"Synthetic GUI item")}};
    }
    // [MS-PST] 2.3.3.2: a Unicode PC value, large enough to require several data blocks.
    writer::ContentProperty body;
    body.prop_id = 0x1000;
    body.prop_type = 0x001F;
    body.value.resize(24000);
    for (size_t i = 0; i < body.value.size(); i += 2)
        body.value[i] = 'A';
    message.properties.push_back(std::move(body));
    writer::ContentAttachment attachment;
    attachment.has_payload = true;
    attachment.payload.resize(12000, 0x5A);
    if (complete)
        attachment.properties = {{0x3705, 0x0003, {1, 0, 0, 0}},
                                 {0x3707, 0x001F, text(u"synthetic.bin")}};
    message.attachment_objects.push_back(std::move(attachment));
    message.attachments.rows.push_back({});
    for (int i = 0; i < count; ++i)
        folder.messages.push_back(message);
    request.folders.push_back(std::move(folder));
    auto built = writer::build_store(request);
    if (!built.ok()) {
        std::fprintf(stderr, "%s\n", ost2pst::util::format_error(built.error()).c_str());
        return 1;
    }
    const auto& image = built.value().image;
    std::ofstream out(std::filesystem::path(argv[1]), std::ios::binary);
    out.write(reinterpret_cast<const char*>(image.bytes.data()),
              static_cast<std::streamsize>(image.bytes.size()));
    out.close();
    if (!out)
        return 1;
    if (corrupt) {
        uint64_t bid = 0;
        {
            auto file = ost2pst::util::FileReader::open(argv[1]);
            if (!file.ok())
                return 1;
            ost2pst::ltp::LtpReadOptions options;
            options.scan_blocks = false;
            options.build_folders = false;
            auto read = ost2pst::ltp::read_ltp(file.value(), options);
            if (!read.ok())
                return 1;
            auto manifest = ost2pst::msg::build_mailbox_manifest(read.value());
            if (!manifest.ok() || manifest.value().items.empty())
                return 1;
            auto node = read.value().nodes.node(manifest.value().items.front().source_nid);
            if (!node.ok())
                return 1;
            bid = node.value().bid_data;
        }
        bool changed = false;
        std::fstream damaged(std::filesystem::path(argv[1]),
                             std::ios::binary | std::ios::in | std::ios::out);
        for (const auto& block : image.blocks)
            if (block.bid == bid) {
                damaged.seekp(static_cast<std::streamoff>(block.ib + 3));
                // Deliberately leave a bad CRC on one item, retaining a readable source index.
                damaged.put(static_cast<char>(image.bytes[block.ib + 3] ^ 0x40));
                changed = true;
            }
        if (!changed || !damaged)
            return 1;
    }
    // Layout metadata from the writer itself, used to cut inside block bodies/trailers.
    std::printf("{\"bbt\":%llu,\"nbt\":%llu,\"blocks\":[",
                static_cast<unsigned long long>(image.bbt_root_ib),
                static_cast<unsigned long long>(image.nbt_root_ib));
    bool first = true;
    for (const auto& block : image.blocks) {
        std::printf("%s{\"ib\":%llu,\"cb\":%u}", first ? "" : ",",
                    static_cast<unsigned long long>(block.ib), static_cast<unsigned>(block.cb));
        first = false;
    }
    std::printf("]}\n");
    return 0;
}
