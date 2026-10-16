// Research probe (not production code): enumerate the Outlook blank-PST oracle through libpff's own
// public API. The oracle is bCryptMethod 1, which the project's reader refuses on purpose, so the
// independent view of its Messaging layer comes from libpff, not from our decoder.
// Nothing here feeds the writer; it records what an Outlook-created empty PST actually contains.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "libpff.h"

namespace {

void print_error(libpff_error_t* error) {
    // This generated libpff.h exposes no error-message getter, so the probe only records that the
    // call failed; the surrounding counters are what the comparison uses.
    (void)error;
    std::printf("  libpff call failed\n");
    libpff_error_free(&error);
}

std::string folder_name(libpff_item_t* folder) {
    size_t size = 0;
    if (libpff_folder_get_utf8_name_size(folder, &size, nullptr) <= 0) {
        return "<unreadable>";
    }
    std::vector<char> buffer(size + 1, 0);
    if (libpff_folder_get_utf8_name(folder, reinterpret_cast<uint8_t*>(buffer.data()), size + 1,
                                    nullptr) <= 0) {
        return "<unreadable>";
    }
    return std::string(buffer.data());
}

void walk_folder(libpff_item_t* folder, int depth) {
    uint8_t type = 0;
    libpff_folder_get_type(folder, &type, nullptr);
    int sub_folders = 0;
    libpff_folder_get_number_of_sub_folders(folder, &sub_folders, nullptr);
    int sub_messages = 0;
    libpff_folder_get_number_of_sub_messages(folder, &sub_messages, nullptr);
    int sub_associated = 0;
    libpff_folder_get_number_of_sub_associated_contents(folder, &sub_associated, nullptr);
    for (int depth_index = 0; depth_index < depth; ++depth_index) {
        std::printf("  ");
    }
    std::printf("folder type 0x%02X name=%s sub_folders=%d sub_messages=%d sub_associated=%d\n",
                type, folder_name(folder).c_str(), sub_folders, sub_messages, sub_associated);
    for (int index = 0; index < sub_folders; ++index) {
        libpff_item_t* child = nullptr;
        libpff_error_t* error = nullptr;
        if (libpff_folder_get_sub_folder(folder, index, &child, &error) <= 0) {
            std::printf("  sub_folder %d unreadable\n", index);
            if (error != nullptr) {
                print_error(error);
            }
            continue;
        }
        walk_folder(child, depth + 1);
        libpff_item_free(&child, nullptr);
    }
}

void dump_record_sets(libpff_item_t* item, const char* label) {
    int record_sets = 0;
    if (libpff_item_get_number_of_record_sets(item, &record_sets, nullptr) <= 0) {
        std::printf("%s: no record sets\n", label);
        return;
    }
    std::printf("%s: %d record set(s)\n", label, record_sets);
    for (int set_index = 0; set_index < record_sets; ++set_index) {
        libpff_record_set_t* record_set = nullptr;
        libpff_error_t* error = nullptr;
        if (libpff_item_get_record_set_by_index(item, set_index, &record_set, &error) <= 0) {
            std::printf("  record set %d unreadable\n", set_index);
            if (error != nullptr) {
                print_error(error);
            }
            continue;
        }
        int entries = 0;
        libpff_record_set_get_number_of_entries(record_set, &entries, nullptr);
        std::printf("  record set %d: %d entries\n", set_index, entries);
        for (int entry_index = 0; entry_index < entries; ++entry_index) {
            libpff_record_entry_t* entry = nullptr;
            libpff_error_t* entry_error = nullptr;
            if (libpff_record_set_get_entry_by_index(record_set, entry_index, &entry,
                                                     &entry_error) <= 0) {
                std::printf("    entry %u unreadable\n", entry_index);
                if (entry_error != nullptr) {
                    print_error(entry_error);
                }
                continue;
            }
            uint32_t entry_type = 0;
            uint32_t value_type = 0;
            size_t data_size = 0;
            libpff_record_entry_get_entry_type(entry, &entry_type, nullptr);
            libpff_record_entry_get_value_type(entry, &value_type, nullptr);
            libpff_record_entry_get_data_size(entry, &data_size, nullptr);
            std::string rendered;
            if (value_type == 0x001F || value_type == 0x001E) {
                size_t utf16_size = 0;
                if (libpff_record_entry_get_data_as_utf16_string_size(entry, &utf16_size, nullptr) >
                    0) {
                    std::vector<uint16_t> buffer(utf16_size + 1, 0);
                    if (libpff_record_entry_get_data_as_utf16_string(entry, buffer.data(),
                                                                     utf16_size, nullptr) > 0) {
                        for (uint16_t unit : buffer) {
                            if (unit == 0) {
                                break;
                            }
                            rendered.push_back(unit < 0x80 ? static_cast<char>(unit) : '?');
                        }
                    }
                }
            } else if (value_type == 0x0003 || value_type == 0x0002 || value_type == 0x000B) {
                uint32_t value = 0;
                if (libpff_record_entry_get_data_as_32bit_integer(entry, &value, nullptr) > 0) {
                    char number[32];
                    std::snprintf(number, sizeof(number), "%u", value);
                    rendered = number;
                }
            }
            std::printf("    entry 0x%04X type 0x%04X data_size %zu %s\n", entry_type, value_type,
                        data_size, rendered.c_str());
            libpff_record_entry_free(&entry, nullptr);
        }
        libpff_record_set_free(&record_set, nullptr);
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: blank_pst_libpff_probe <pst>\n");
        return 2;
    }
    libpff_file_t* file = nullptr;
    libpff_error_t* error = nullptr;
    if (libpff_file_initialize(&file, &error) <= 0) {
        std::printf("libpff cannot allocate a file handle\n");
        if (error != nullptr) {
            print_error(error);
        }
        return 2;
    }
    if (libpff_file_open(file, argv[1], LIBPFF_OPEN_READ, &error) <= 0) {
        std::printf("libpff cannot open %s\n", argv[1]);
        if (error != nullptr) {
            print_error(error);
        }
        return 2;
    }
    std::printf("libpff opened %s\n", argv[1]);

    size_t size = 0;
    uint8_t content_type = 0;
    uint8_t file_type = 0;
    uint8_t encryption_type = 0;
    libpff_file_get_size(file, &size, nullptr);
    libpff_file_get_content_type(file, &content_type, nullptr);
    libpff_file_get_type(file, &file_type, nullptr);
    libpff_file_get_encryption_type(file, &encryption_type, nullptr);
    std::printf("size %zu content_type %d file_type %d encryption_type %d\n", size, content_type,
                file_type, encryption_type);

    libpff_item_t* message_store = nullptr;
    int got = libpff_file_get_message_store(file, &message_store, &error);
    if (got == 1) {
        dump_record_sets(message_store, "message store");
        libpff_item_free(&message_store, nullptr);
    } else {
        std::printf("message store: get returned %d\n", got);
        if (error != nullptr) {
            print_error(error);
        }
    }

    libpff_item_t* name_to_id = nullptr;
    got = libpff_file_get_name_to_id_map(file, &name_to_id, &error);
    if (got == 1) {
        uint32_t entries = 0;
        libpff_item_get_number_of_entries(name_to_id, &entries, nullptr);
        std::printf("name-to-id map: %u entries\n", entries);
        libpff_item_free(&name_to_id, nullptr);
    } else {
        std::printf("name-to-id map: get returned %d\n", got);
        if (error != nullptr) {
            print_error(error);
        }
    }

    libpff_item_t* root_folder = nullptr;
    got = libpff_file_get_root_folder(file, &root_folder, &error);
    if (got == 1) {
        walk_folder(root_folder, 0);
        libpff_item_free(&root_folder, nullptr);
    } else {
        std::printf("root folder: get returned %d\n", got);
        if (error != nullptr) {
            print_error(error);
        }
    }

    int orphans = 0;
    libpff_file_get_number_of_orphan_items(file, &orphans, nullptr);
    std::printf("orphan items %d\n", orphans);

    libpff_file_free(&file, nullptr);
    std::printf("COMPLETE\n");
    return 0;
}
