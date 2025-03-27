#define _GNU_SOURCE       // For FTW_SKIP_SUBTREE if available
#define _XOPEN_SOURCE 700 // Required for nftw, strptime
#define _DEFAULT_SOURCE   // For S_IF* constants if needed, nftw flags
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>         // For variadic functions (logging)
#include <getopt.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <magic.h>
#include <openssl/sha.h>    // Needed for SHA256_DIGEST_LENGTH constant
#include <openssl/evp.h>    // Use EVP API for hashing
#include <openssl/err.h>    // For error reporting with EVP
#include <ftw.h>            // For file tree walk
#include <libgen.h>         // For dirname
#include <limits.h>         // For PATH_MAX

// --- Constants ---
#define VERSION "1.0"
#define HEADER_MARKER "=== REPO-PACK HEADER ==="
#define CONTENTS_MARKER "=== REPO-PACK CONTENTS ==="
#define FILE_SEPARATOR_PREFIX "----- "
#define FILE_SEPARATOR_SUFFIX " -----"
#define MAX_PATH_LEN 4096
#define HASH_STR_LEN (SHA256_DIGEST_LENGTH * 2 + 1)
#define READ_BUFFER_SIZE 8192

// --- Global Flags ---
static bool verbose_mode = false;

// --- Logging Utilities ---

// Log general error messages
void log_error(const char *fmt, ...) {
    va_list args;
    fprintf(stderr, "Error: ");
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

// Log error messages related to syscalls (includes errno string)
void log_perror(const char *msg) {
    fprintf(stderr, "Error: %s: %s\n", msg, strerror(errno));
}

// Log warnings
void log_warning(const char *fmt, ...) {
    va_list args;
    fprintf(stderr, "Warning: ");
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

// Log verbose messages (only if verbose_mode is enabled)
void log_verbose(const char *fmt, ...) {
    if (verbose_mode) {
        va_list args;
        fprintf(stderr, "Verbose: ");
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, "\n");
    }
}

// Print OpenSSL errors
void log_openssl_error(const char *context) {
    unsigned long err_code;
    char err_buf[256];
    log_error("%s failed.", context);
    while ((err_code = ERR_get_error()) != 0) {
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        fprintf(stderr, "  OpenSSL: %s\n", err_buf);
    }
}

// Die on fatal errors (usually memory allocation)
void die(const char *msg) {
    log_perror(msg);
    exit(EXIT_FAILURE);
}

// --- Data Structures ---
typedef struct {
    char path[MAX_PATH_LEN];
    char type;          // 'd' for dir, 'f' for file, '!' for skipped
    char sha256_str[HASH_STR_LEN];
    off_t size;         // Use off_t for file size
    off_t start_offset; // Use off_t for offsets
    off_t end_offset;   // Use off_t for offsets
    char reason[100];   // Reason for skipping
} FileInfo;

typedef struct {
    FileInfo *items;
    size_t count;
    size_t capacity;
    magic_t magic_cookie; // Managed by pack/unpack
    const char *base_path;
    size_t base_path_len;
    bool suppress_bin_warning; // True if --skip-bin was used
} FileCollector;

// --- Global Variable (for nftw callback) ---
static FileCollector global_collector; // Use a static global for nftw

// --- Utility Functions ---

void usage(const char *prog_name) {
    fprintf(stderr, "repo-pack: Flatten and restore directory structures.\n\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [options] <source_dir>             Pack directory to stdout\n", prog_name);
    fprintf(stderr, "  %s -x [options] <archive_file>        Extract archive\n", prog_name);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -x, --extract          Extract mode: restore from an archive file.\n");
    fprintf(stderr, "  -o, --output <path>    Output directory for extraction (default: current dir).\n");
    fprintf(stderr, "  -v, --verbose          Enable verbose output during operation.\n");
    fprintf(stderr, "      --verify           Verify SHA-256 checksums during extraction.\n");
    fprintf(stderr, "      --skip-bin         (Pack mode) Silently skip binary files without warning.\n");
    fprintf(stderr, "      --help             Show this help message.\n");
    fprintf(stderr, "\nVersion: %s\n", VERSION);
    exit(EXIT_FAILURE);
}

// Convert binary hash to hex string
void sha256_to_hex(const unsigned char hash[SHA256_DIGEST_LENGTH], char hex_str[HASH_STR_LEN]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_str + (i * 2), "%02x", hash[i]);
    }
    hex_str[HASH_STR_LEN - 1] = '\0';
}

// Convert hex string to binary hash
int hex_to_sha256(const char hex_str[HASH_STR_LEN -1], unsigned char hash[SHA256_DIGEST_LENGTH]) {
    if (strlen(hex_str) != SHA256_DIGEST_LENGTH * 2) {
        return -1; // Invalid length
    }
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        unsigned int byte;
        if (sscanf(hex_str + (i * 2), "%2x", &byte) != 1) {
            return -1; // Invalid hex character
        }
        hash[i] = (unsigned char)byte;
    }
    return 0;
}

// Calculate SHA256 hash of a file using EVP API
int calculate_sha256(const char *filepath, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    FILE *file = NULL;
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    unsigned char buffer[READ_BUFFER_SIZE];
    size_t bytes_read;
    unsigned int hash_len_out;
    int result = -1; // Default to failure

    file = fopen(filepath, "rb");
    if (!file) {
        log_warning("Could not open file %s for hashing: %s", filepath, strerror(errno));
        goto cleanup;
    }

    md = EVP_sha256();
    if (md == NULL) {
        log_openssl_error("EVP_sha256()");
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        log_openssl_error("EVP_MD_CTX_new()");
        goto cleanup;
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        log_openssl_error("EVP_DigestInit_ex()");
        goto cleanup;
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            log_openssl_error("EVP_DigestUpdate()");
            goto cleanup;
        }
    }

    if (ferror(file)) {
        log_warning("Error reading file %s for hashing: %s", filepath, strerror(errno));
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len_out) != 1) {
        log_openssl_error("EVP_DigestFinal_ex()");
        goto cleanup;
    }

    if (hash_len_out != SHA256_DIGEST_LENGTH) {
        log_error("SHA256 output length mismatch (%u != %d).", hash_len_out, SHA256_DIGEST_LENGTH);
        goto cleanup;
    }

    result = 0; // Success

cleanup:
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    if (file != NULL) {
        fclose(file);
    }
    return result;
}


// Check if a file is likely binary using libmagic
bool is_binary(magic_t magic_cookie, const char *filepath) {
    const char *magic_full = magic_file(magic_cookie, filepath);
    if (magic_full == NULL) {
        log_warning("Cannot determine type of %s: %s", filepath, magic_error(magic_cookie));
        return true; // Treat as binary if unsure
    }

    // Simplistic check based on previous logic
    if (strstr(magic_full, "text") != NULL) {
        if (strstr(magic_full, "postscript") != NULL || strstr(magic_full, "pdf") != NULL) return true;
        return false; // Likely text
    }
    if (strstr(magic_full, "empty") != NULL) {
        return false; // Empty files are not binary
    }
    return true; // If not text or empty, assume binary
}

// Add FileInfo to dynamic array (using the global collector)
void add_file_info(FileCollector *collector, FileInfo info) {
    if (collector->count >= collector->capacity) {
        collector->capacity = (collector->capacity == 0) ? 16 : collector->capacity * 2;
        FileInfo *new_items = realloc(collector->items, collector->capacity * sizeof(FileInfo));
        if (!new_items) {
            free(collector->items);
            die("Failed to reallocate memory for file list");
        }
        collector->items = new_items;
    }
    collector->items[collector->count++] = info;
}

// nftw callback function for packing
int pack_walker(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    FileCollector *collector = &global_collector;
//    fprintf(stderr, "DEBUG: pack_walker entry: fpath='%s', type=%d, level=%d\n", fpath, typeflag, ftwbuf->level);
    (void)ftwbuf; // Mark as potentially unused

    if (strcmp(fpath, collector->base_path) == 0) {
//        fprintf(stderr, "DEBUG: Skipping root path.\n");
        return 0;
    }

    const char *relative_path_ptr = NULL;
    if (strncmp(fpath, collector->base_path, collector->base_path_len) == 0) {
        relative_path_ptr = fpath + collector->base_path_len;
        if (relative_path_ptr[0] == '/') {
            relative_path_ptr++;
        }
    } else {
//        fprintf(stderr, "DEBUG: WARNING - fpath '%s' does not start with base_path '%s'\n", fpath, collector->base_path);
        log_warning("Path '%s' unexpected, does not start with base path. Skipping.", fpath);
        return 0;
    }
//    fprintf(stderr, "DEBUG:   Relative path calculated: '%s'\n", relative_path_ptr);

    // *** DIAGNOSTIC CHANGE: Only return 0 for .git to test nftw continuation ***
    if (strncmp(relative_path_ptr, ".git/", 5) == 0 || strcmp(relative_path_ptr, ".git") == 0) {
        log_verbose("Skipping git path: %s", relative_path_ptr);
//        fprintf(stderr, "DEBUG: Skipping .git path: %s (and returning 0)\n", relative_path_ptr); // DEBUG
        // #ifdef FTW_SKIP_SUBTREE
        // if (typeflag == FTW_D && strcmp(relative_path_ptr, ".git") == 0) {
        //    return FTW_SKIP_SUBTREE; // Temporarily disabled
        // }
        // #endif
        return 0; // Always return 0 for .git paths for now to see if siblings are processed
    }
    // *** END DIAGNOSTIC CHANGE ***


    FileInfo info = {0};
    strncpy(info.path, relative_path_ptr, MAX_PATH_LEN - 1);
    info.path[MAX_PATH_LEN - 1] = '\0';

    if (typeflag == FTW_D) {
        info.type = 'd';
        log_verbose("Found directory: %s", info.path);
//        fprintf(stderr, "DEBUG: Adding directory: %s\n", info.path); // DEBUG
        add_file_info(collector, info);
    } else if (typeflag == FTW_F) {
//        fprintf(stderr, "DEBUG: Processing file: %s\n", info.path); // DEBUG
        info.size = sb->st_size;
        if (is_binary(collector->magic_cookie, fpath)) {
            info.type = '!';
            snprintf(info.reason, sizeof(info.reason), "Skipped: Binary file detected");
            if (!collector->suppress_bin_warning) {
                log_warning("%s (%s)", info.path, info.reason);
            } else {
                log_verbose("Skipping binary file: %s", info.path);
            }
//            fprintf(stderr, "DEBUG: Adding skipped (binary) file: %s\n", info.path); // DEBUG
            add_file_info(collector, info);
        } else {
            info.type = 'f';
            unsigned char hash[SHA256_DIGEST_LENGTH];
            if (calculate_sha256(fpath, hash) == 0) {
                sha256_to_hex(hash, info.sha256_str);
                log_verbose("Found text file: %s (sha256: %s)", info.path, info.sha256_str);
//                fprintf(stderr, "DEBUG: Adding text file: %s\n", info.path); // DEBUG
            } else {
                info.type = '!';
                snprintf(info.reason, sizeof(info.reason), "Skipped: Failed to calculate SHA256 hash");
                log_warning("%s (%s)", info.path, info.reason);
//                fprintf(stderr, "DEBUG: Adding skipped (hash failed) file: %s\n", info.path); // DEBUG
            }
            add_file_info(collector, info);
        }
    } else if (typeflag == FTW_SL || typeflag == FTW_SLN) {
        log_verbose("Skipping symbolic link: %s", info.path);
//        fprintf(stderr, "DEBUG: Skipping symlink: %s\n", info.path); // DEBUG
    } else if (typeflag == FTW_DNR) {
        log_warning("Cannot read directory: %s", fpath);
//        fprintf(stderr, "DEBUG: Cannot read dir: %s\n", fpath); // DEBUG
    } else if (typeflag == FTW_NS) {
        log_warning("Cannot stat file: %s (%s)", fpath, strerror(errno));
//        fprintf(stderr, "DEBUG: Cannot stat file: %s\n", fpath); // DEBUG
        info.type = '!';
        snprintf(info.reason, sizeof(info.reason), "Skipped: Cannot stat file (%s)", strerror(errno));
        add_file_info(collector, info);
    } else {
        log_verbose("Skipping unknown file type %d: %s", typeflag, info.path);
//        fprintf(stderr, "DEBUG: Skipping unknown type %d: %s\n", typeflag, info.path); // DEBUG
    }

    return 0; // Continue traversal
}

// Create directories recursively (like mkdir -p)
int mkdir_recursive(const char *path, mode_t mode) {
    char *path_copy = NULL;
    int result = -1; // Default failure

    path_copy = strdup(path);
    if (!path_copy) {
        log_perror("strdup failed in mkdir_recursive");
        goto cleanup;
    }

    result = 0;
    char *p = path_copy;
    while (*p == '/') p++;

    while (result == 0 && (p = strchr(p, '/')) != NULL) {
        *p = '\0';
        if (mkdir(path_copy, mode) == -1 && errno != EEXIST) {
            log_perror("mkdir failed");
            result = -1;
        } else {
             *p = '/';
             p++;
             while (*p == '/') p++;
        }
    }

    if (result == 0 && mkdir(path, mode) == -1 && errno != EEXIST) {
        char err_buf[MAX_PATH_LEN + 50];
        snprintf(err_buf, sizeof(err_buf), "mkdir failed for final component '%s'", path);
        log_perror(err_buf);
        result = -1;
    }

cleanup:
    free(path_copy);
    return result;
}

// --- Packing Logic ---
int pack_repo(const char *source_dir, FILE *out_fp, bool skip_bin_flag) {
    char abs_source_dir[PATH_MAX];
    int result = 1;
    FILE *src_fp = NULL;

    memset(&global_collector, 0, sizeof(global_collector));
    global_collector.suppress_bin_warning = skip_bin_flag;
    global_collector.magic_cookie = NULL;
    global_collector.items = NULL;

    if (!realpath(source_dir, abs_source_dir)) {
        log_perror("Error getting absolute path for source");
        goto cleanup;
    }
//    fprintf(stderr, "DEBUG: realpath resolved '%s' to '%s'\n", source_dir, abs_source_dir);
    global_collector.base_path = abs_source_dir;
    global_collector.base_path_len = strlen(abs_source_dir);
//    fprintf(stderr, "DEBUG: base_path_len = %zu\n", global_collector.base_path_len);

    global_collector.magic_cookie = magic_open(MAGIC_MIME_TYPE | MAGIC_SYMLINK | MAGIC_ERROR);
    if (global_collector.magic_cookie == NULL) {
        log_error("Unable to initialize magic library");
        goto cleanup;
    }
    if (magic_load(global_collector.magic_cookie, NULL) != 0) {
        log_error("Cannot load magic database - %s", magic_error(global_collector.magic_cookie));
        goto cleanup;
    }

    log_verbose("Starting directory scan: %s", abs_source_dir);
//    fprintf(stderr, "DEBUG: Calling nftw on '%s'\n", abs_source_dir);

    if (nftw(abs_source_dir, pack_walker, 20, FTW_PHYS) == -1) {
        log_perror("nftw failed");
        goto cleanup;
    }

    log_verbose("Directory scan complete. Found %zu items.", global_collector.count);
//    fprintf(stderr, "DEBUG: nftw finished. Found %zu items.\n", global_collector.count);

    // --- Write Header ---
    fprintf(out_fp, "%s\n", HEADER_MARKER);
    fprintf(out_fp, "FORMAT: repo-pack v%s\n", VERSION);
    time_t now = time(NULL);
    struct tm *tminfo = gmtime(&now);
    char timestamp[100];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S UTC", tminfo);
    fprintf(out_fp, "TIMESTAMP: %s\n", timestamp);
    fprintf(out_fp, "\n# Directory Structure:\n");
    for (size_t i = 0; i < global_collector.count; ++i) {
        FileInfo *info = &global_collector.items[i];
        if (info->type == 'd') fprintf(out_fp, "[d] %s/\n", info->path);
        else if (info->type == 'f') fprintf(out_fp, "[f] %s  (sha256: %s)\n", info->path, info->sha256_str);
    }
    bool skipped_header_written = false;
    for (size_t i = 0; i < global_collector.count; ++i) {
        FileInfo *info = &global_collector.items[i];
        if (info->type == '!') {
            if (!skipped_header_written) {
                fprintf(out_fp, "\n# Skipped Files:\n");
                skipped_header_written = true;
            }
            fprintf(out_fp, "[!] %s (%s)\n", info->path, info->reason);
        }
    }
    fprintf(out_fp, "\n# Content Boundaries:\n");
    off_t current_offset = 0;
    for (size_t i = 0; i < global_collector.count; ++i) {
        FileInfo *info = &global_collector.items[i];
        if (info->type == 'f') {
            size_t sep_len = strlen(FILE_SEPARATOR_PREFIX) + strlen(info->path) + strlen(FILE_SEPARATOR_SUFFIX) + 1;
            current_offset += sep_len;
            info->start_offset = current_offset;
            info->end_offset = info->start_offset + info->size;
            fprintf(out_fp, "[%s] START_OFFSET: %lld  END_OFFSET: %lld\n",
                    info->path, (long long)info->start_offset, (long long)info->end_offset);
            current_offset = info->end_offset + (info->size > 0 ? 1 : 0);
        }
    }

    // --- Write Content ---
    fprintf(out_fp, "\n%s\n", CONTENTS_MARKER);
    for (size_t i = 0; i < global_collector.count; ++i) {
        FileInfo *info = &global_collector.items[i];
        if (info->type == 'f') {
            fprintf(out_fp, "%s%s%s\n", FILE_SEPARATOR_PREFIX, info->path, FILE_SEPARATOR_SUFFIX);
            char full_src_path[PATH_MAX + MAX_PATH_LEN];
            snprintf(full_src_path, sizeof(full_src_path), "%s/%s", abs_source_dir, info->path);
            src_fp = fopen(full_src_path, "rb");
            if (!src_fp) {
                log_warning("Could not open source file %s during content writing: %s. Skipping content.", full_src_path, strerror(errno));
                continue;
            }
            unsigned char buffer[READ_BUFFER_SIZE];
            size_t bytes_read;
            while ((bytes_read = fread(buffer, 1, sizeof(buffer), src_fp)) > 0) {
                if (fwrite(buffer, 1, bytes_read, out_fp) != bytes_read) {
                    log_perror("fwrite error during content writing");
                    fclose(src_fp); src_fp = NULL;
                    goto cleanup;
                }
            }
            if (ferror(src_fp)) {
                log_warning("Error reading source file %s: %s. Content might be incomplete.", full_src_path, strerror(errno));
            }
            fclose(src_fp); src_fp = NULL;
            if (info->size > 0) {
                fprintf(out_fp, "\n");
            }
        }
    }

    result = 0; // Success!

cleanup:
    if (src_fp != NULL) fclose(src_fp);
    if (global_collector.magic_cookie != NULL) magic_close(global_collector.magic_cookie);
    free(global_collector.items);
    memset(&global_collector, 0, sizeof(global_collector));
    if (result == 0) log_verbose("Packing complete.");
    else log_error("Packing failed.");
    return result;
}

// --- Unpacking Logic ---
int unpack_repo(const char *archive_path, const char *output_dir, bool verify) {
    FILE *in_fp = NULL;
    FILE *out_fp = NULL;
    FileCollector parsed_files = {0};
    char original_cwd[PATH_MAX] = {0};
    char *path_copy = NULL;
    int result = 1;
    int unpack_errors = 0;

    parsed_files.items = NULL;

    in_fp = strcmp(archive_path, "-") == 0 ? stdin : fopen(archive_path, "r");
    if (!in_fp) {
        log_error("Opening archive file '%s': %s", archive_path, strerror(errno));
        goto cleanup;
    }
    log_verbose("Opened archive %s", strcmp(archive_path, "-") == 0 ? "<stdin>" : archive_path);

    char line[MAX_PATH_LEN + 200];
    bool in_header = false;
    bool header_parsed = false;
    off_t content_start_pos = -1;

    // --- Parse Header ---
    while (fgets(line, sizeof(line), in_fp)) {
        line[strcspn(line, "\r\n")] = 0;

        if (!in_header) {
            if (strcmp(line, HEADER_MARKER) == 0) {
                in_header = true;
                log_verbose("Found header marker.");
            }
            continue;
        }

        if (strcmp(line, CONTENTS_MARKER) == 0) {
            content_start_pos = ftello(in_fp);
            if (content_start_pos == -1) {
                log_perror("ftello after CONTENTS_MARKER failed");
                goto cleanup;
            }
            log_verbose("Found contents marker at offset %lld.", (long long)content_start_pos);
            header_parsed = true;
            break;
        }

        if (strncmp(line, "[d] ", 4) == 0) {
            FileInfo info = { .type = 'd' };
            size_t path_len = strlen(line + 4);
            // *** Fix strncpy warning ***
            // Copy len-1 to guarantee space for null terminator if trailing / exists
            if (path_len > 0 && path_len < sizeof(info.path)) {
                 size_t copy_len = path_len;
                 // Check for trailing slash and adjust length to exclude it but keep space
                 if (line[4 + path_len - 1] == '/') {
                      copy_len = path_len - 1;
                 }
                 // Copy up to one less than the buffer size
                 if (copy_len >= sizeof(info.path)) {
                     copy_len = sizeof(info.path) - 1; // Ensure space for null terminator
                 }
                 strncpy(info.path, line + 4, copy_len);
                 info.path[copy_len] = '\0'; // Null terminate
                 log_verbose("Parsed directory: %s", info.path);
                 add_file_info(&parsed_files, info);
            } else if (path_len > 0) { // Path is too long
                log_warning("Directory path too long in header: %s", line);
            } else { // Empty path
                log_warning("Empty directory path in header: %s", line);
            }
            // *** End fix ***
        } else if (strncmp(line, "[f] ", 4) == 0) {
            FileInfo info = { .type = 'f' };
            char *sha_start = strstr(line, "  (sha256: ");
            if (sha_start) {
                size_t path_len = sha_start - (line + 4);
                if (path_len < sizeof(info.path)) {
                    strncpy(info.path, line + 4, path_len); info.path[path_len] = '\0';
                    char *sha_end = strchr(sha_start, ')');
                    if (sha_end) {
                        const char *hash_ptr = sha_start + strlen("  (sha256: ");
                        size_t hash_len = sha_end - hash_ptr;
                        if (hash_len == HASH_STR_LEN - 1) {
                            strncpy(info.sha256_str, hash_ptr, hash_len); info.sha256_str[hash_len] = '\0';
                            log_verbose("Parsed file: %s (sha256: %s)", info.path, info.sha256_str);
                            add_file_info(&parsed_files, info);
                        } else log_warning("Malformed sha256 length in header: %s", line);
                    } else log_warning("Malformed file line (missing ')'): %s", line);
                } else log_warning("Parsed path too long in header: %s", line);
            } else log_warning("Malformed file line (missing sha256 marker): %s", line);
        } else if (strncmp(line, "[!] ", 4) == 0) {
            log_verbose("Noted skipped file from header: %s", line + 4);
        } else if (strncmp(line, "[", 1) == 0 && strstr(line, "] START_OFFSET: ") != NULL) {
            char current_path[MAX_PATH_LEN];
            char *path_end = strchr(line, ']');
            if (path_end) {
                size_t path_len = path_end - (line + 1);
                if (path_len < sizeof(current_path)) {
                    strncpy(current_path, line + 1, path_len); current_path[path_len] = '\0';
                    long long start_ll, end_ll;
                    if (sscanf(path_end + 1, " START_OFFSET: %lld END_OFFSET: %lld", &start_ll, &end_ll) == 2) {
                        bool found = false;
                        for (size_t i = 0; i < parsed_files.count; ++i) {
                            if (parsed_files.items[i].type == 'f' && strcmp(parsed_files.items[i].path, current_path) == 0) {
                                parsed_files.items[i].start_offset = (off_t)start_ll;
                                parsed_files.items[i].end_offset = (off_t)end_ll;
                                parsed_files.items[i].size = end_ll - start_ll;
                                if (parsed_files.items[i].size < 0) {
                                     log_warning("Invalid boundary for %s (end < start). Treating as empty.", current_path);
                                     parsed_files.items[i].size = 0;
                                }
                                log_verbose("Parsed boundary for %s: %lld - %lld (size %lld)",
                                            current_path, (long long)start_ll, (long long)end_ll, (long long)parsed_files.items[i].size);
                                found = true;
                                break;
                            }
                        }
                        if (!found) log_verbose("Warning - boundary found for unknown/non-file path: %s", current_path);
                    } else log_warning("Malformed boundary line (sscanf failed): %s", line);
                } else log_warning("Path too long in boundary line: %s", line);
            } else log_warning("Malformed boundary line (missing ']'): %s", line);
        }
    } // end while(fgets)

    if (!header_parsed || content_start_pos == -1) {
        log_error("Invalid or incomplete repo-pack archive. Header/content marker missing.");
        goto cleanup;
    }

    if (!getcwd(original_cwd, sizeof(original_cwd))) {
        log_perror("getcwd failed");
        goto cleanup;
    }

    if (mkdir_recursive(output_dir, 0755) != 0 && errno != EEXIST) {
        log_error("Could not create or access output directory '%s'", output_dir);
        goto cleanup;
    }

    if (chdir(output_dir) != 0) {
        log_error("Could not change to output directory '%s': %s", output_dir, strerror(errno));
        goto cleanup;
    }
    log_verbose("Changed to output directory: %s", output_dir);

    for (size_t i = 0; i < parsed_files.count; ++i) {
        if (parsed_files.items[i].type == 'd') {
            log_verbose("Ensuring directory exists: %s", parsed_files.items[i].path);
            if (mkdir_recursive(parsed_files.items[i].path, 0755) != 0 && errno != EEXIST) {
                log_warning("Failed to create directory %s", parsed_files.items[i].path);
                unpack_errors++;
            }
        }
    }

    for (size_t i = 0; i < parsed_files.count; ++i) {
        FileInfo *info = &parsed_files.items[i];
        if (info->type == 'f') {
            bool file_write_ok = false;
            log_verbose("Extracting file: %s (size %lld)", info->path, (long long)info->size);

            free(path_copy);
            path_copy = strdup(info->path);
            if (!path_copy) die("strdup failed");
            char *parent_dir = dirname(path_copy);
            if (parent_dir && strcmp(parent_dir, ".") != 0 && strcmp(parent_dir, "/") != 0) {
                if (mkdir_recursive(parent_dir, 0755) != 0 && errno != EEXIST) {
                    log_warning("Failed to create parent directory %s for file %s", parent_dir, info->path);
                }
            }

            out_fp = fopen(info->path, "wb");
            if (!out_fp) {
                log_error("Could not create output file '%s': %s", info->path, strerror(errno));
                unpack_errors++;
                continue;
            }

            if (fseeko(in_fp, content_start_pos + info->start_offset, SEEK_SET) != 0) {
                log_error("Failed to seek in archive for file '%s' (offset %lld): %s", info->path, (long long)(content_start_pos + info->start_offset), strerror(errno));
                unpack_errors++;
                fclose(out_fp); out_fp = NULL;
                remove(info->path);
                continue;
            }

            unsigned char buffer[READ_BUFFER_SIZE];
            off_t remaining = info->size;
            while (remaining > 0) {
                size_t to_read = (remaining < (off_t)sizeof(buffer)) ? (size_t)remaining : sizeof(buffer);
                size_t bytes_read = fread(buffer, 1, to_read, in_fp);
                if (bytes_read == 0) {
                    if (feof(in_fp)) { if (remaining > 0) log_error("Unexpected EOF reading content for '%s'. Expected %lld more bytes.", info->path, (long long)remaining); }
                    else { log_error("Failed reading archive content for '%s': %s", info->path, strerror(errno)); }
                    unpack_errors++;
                    goto next_file_unpack; // Renamed label
                }
                if (fwrite(buffer, 1, bytes_read, out_fp) != bytes_read) {
                    log_error("Failed writing to output file '%s': %s", info->path, strerror(errno));
                    unpack_errors++;
                    goto next_file_unpack; // Renamed label
                }
                remaining -= bytes_read;
            }
            file_write_ok = (remaining == 0);

        next_file_unpack: // Renamed label
            fclose(out_fp); out_fp = NULL;

            if (!file_write_ok) {
                remove(info->path);
                continue;
            }

            if (verify) {
                log_verbose("Verifying SHA256 for %s...", info->path);
                unsigned char actual_hash[SHA256_DIGEST_LENGTH];
                unsigned char expected_hash[SHA256_DIGEST_LENGTH];
                if (calculate_sha256(info->path, actual_hash) == 0) {
                    if (hex_to_sha256(info->sha256_str, expected_hash) == 0) {
                        if (memcmp(actual_hash, expected_hash, SHA256_DIGEST_LENGTH) == 0) {
                            log_verbose("SHA256 OK: %s", info->path);
                        } else {
                            log_error("SHA256 Verification FAILED for file: %s", info->path);
                            char actual_hash_str[HASH_STR_LEN];
                            sha256_to_hex(actual_hash, actual_hash_str);
                            fprintf(stderr, "  Expected: %s\n", info->sha256_str);
                            fprintf(stderr, "  Actual:   %s\n", actual_hash_str);
                            unpack_errors++;
                        }
                    } else log_warning("Could not parse expected SHA256 for %s. Cannot verify.", info->path);
                } else log_warning("Could not calculate SHA256 for created file %s. Cannot verify.", info->path);
            }
        }
    }

    result = (unpack_errors == 0) ? 0 : 1;

cleanup:
    free(path_copy);
    if (out_fp != NULL) fclose(out_fp);
    if (original_cwd[0] != '\0' && chdir(original_cwd) != 0) {
        log_warning("Could not change back to original directory '%s': %s", original_cwd, strerror(errno));
    }
    if (in_fp != NULL && in_fp != stdin) fclose(in_fp);
    free(parsed_files.items);

    if (result == 0) log_verbose("Unpacking completed successfully.");
    else {
        if (unpack_errors > 0) log_error("Unpacking completed with %d error(s).", unpack_errors);
        else log_error("Unpacking failed due to an early error.");
    }
    return result;
}


// --- Main Function ---
int main(int argc, char *argv[]) {
    bool extract_mode = false;
    bool verify = false;
    bool skip_bin_flag = false;
    const char *output_dir = ".";
    const char *prog_name = argv[0];
    int return_code = 1;

    verbose_mode = false;

    struct option long_options[] = {
        {"extract", no_argument, 0, 'x'},
        {"output", required_argument, 0, 'o'},
        {"verbose", no_argument, 0, 'v'},
        {"verify", no_argument, 0, 1},
        {"skip-bin", no_argument, 0, 2},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "xo:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'x': extract_mode = true; break;
            case 'o': output_dir = optarg; break;
            case 'v': verbose_mode = true; break;
            case 'h': usage(prog_name); return 0;
            case 1: verify = true; break;
            case 2: skip_bin_flag = true; break;
            case '?': fprintf(stderr, "Try '%s --help' for more information.\n", prog_name); goto cleanup;
            default: usage(prog_name); goto cleanup;
        }
    }

    if (optind >= argc) {
        log_error("Missing source directory or archive file.");
        usage(prog_name);
        goto cleanup;
    }
    if (argc - optind > 1) {
        log_error("Too many non-option arguments.");
        usage(prog_name);
        goto cleanup;
    }
    const char *source_path = argv[optind];

    if (extract_mode) {
        if (skip_bin_flag) log_warning("--skip-bin option is ignored in extraction mode.");
        log_verbose("Mode: Extract, Archive: %s, Output Dir: %s, Verify: %s",
                    source_path, output_dir, verify ? "Yes" : "No");
        return_code = unpack_repo(source_path, output_dir, verify);
    } else {
        if (verify) log_warning("--verify option is ignored in packing mode.");
        if (strcmp(output_dir, ".") != 0) log_warning("-o/--output option ignored in packing mode.");
        log_verbose("Mode: Pack, Source: %s, Skip Binaries Silently: %s",
                    source_path, skip_bin_flag ? "Yes" : "No");
        struct stat path_stat;
        if (stat(source_path, &path_stat) != 0) {
            log_error("Accessing source '%s': %s", source_path, strerror(errno));
            goto cleanup;
        }
        if (!S_ISDIR(path_stat.st_mode)) {
            log_error("Source '%s' is not a directory.", source_path);
            goto cleanup;
        }
        return_code = pack_repo(source_path, stdout, skip_bin_flag);
    }

cleanup:
    return return_code;
}