#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecItem.h>
#include <Security/SecKeychain.h>

#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

enum {
    OWNER_LENGTH = 32,
    ACCOUNT_CAPACITY = 96,
};

static void release_if_present(CFTypeRef value) {
    if (value != NULL) {
        CFRelease(value);
    }
}

static int report_status(const char *operation, OSStatus status) {
    CFStringRef message = SecCopyErrorMessageString(status, NULL);
    char buffer[512] = {0};
    if (message != NULL &&
        CFStringGetCString(message, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
        fprintf(stderr, "Error: %s failed (%d): %s\n", operation, (int)status, buffer);
    } else {
        fprintf(stderr, "Error: %s failed (%d)\n", operation, (int)status);
    }
    release_if_present(message);
    return 1;
}

static bool valid_helper(const char *path) {
    struct stat metadata = {0};
    if (path[0] != '/' || lstat(path, &metadata) != 0) {
        return false;
    }
    return S_ISREG(metadata.st_mode) && metadata.st_uid == geteuid() &&
           (metadata.st_mode & 0777) == 0500;
}

static bool valid_owner(const char *value) {
    for (size_t index = 0; index < OWNER_LENGTH; ++index) {
        const char character = value[index];
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return value[OWNER_LENGTH] == '\0';
}

static const char *slot_code(const char *suffix) {
    static const struct {
        const char *suffix;
        const char *code;
    } slots[] = {
        {"integrity-trust-state-v1", "1"},
        {"version-policy-trust-state-v1", "2"},
        {"browser-host-ed25519-secret-key-v1", "3"},
        {"browser-host-lifecycle-token-v1", "4"},
        {"organization-api-key-v3", "5"},
        {"x25519-private-key-v3", "6"},
        {"ed25519-secret-key-v3", "7"},
        {"organization-api-key", "8"},
        {"x25519-private-key", "9"},
        {"ed25519-secret-key", "10"},
    };
    for (size_t index = 0; index < sizeof(slots) / sizeof(slots[0]); ++index) {
        if (strcmp(suffix, slots[index].suffix) == 0) {
            return slots[index].code;
        }
    }
    return NULL;
}

static bool parse_account(CFDictionaryRef attributes,
                          char owner[OWNER_LENGTH + 1],
                          const char **code) {
    CFTypeRef account_value = CFDictionaryGetValue(attributes, kSecAttrAccount);
    if (account_value == NULL || CFGetTypeID(account_value) != CFStringGetTypeID()) {
        return false;
    }
    char account[ACCOUNT_CAPACITY] = {0};
    if (!CFStringGetCString((CFStringRef)account_value, account, sizeof(account),
                            kCFStringEncodingUTF8)) {
        return false;
    }
    char *separator = strchr(account, ':');
    if (separator == NULL || strchr(separator + 1, ':') != NULL ||
        (size_t)(separator - account) != OWNER_LENGTH) {
        return false;
    }
    *separator = '\0';
    if (!valid_owner(account)) {
        return false;
    }
    *code = slot_code(separator + 1);
    if (*code == NULL) {
        return false;
    }
    memcpy(owner, account, OWNER_LENGTH + 1);
    return true;
}

static int run_helper(char *helper_path, char *mode, char *owner, char *code) {
    char *child_arguments[] = {helper_path, mode, owner, code, NULL};
    pid_t child = 0;
    const int spawn_status =
        posix_spawn(&child, helper_path, NULL, NULL, child_arguments, environ);
    if (spawn_status != 0) {
        fprintf(stderr, "Error: starting the stable Keychain helper failed\n");
        return 1;
    }
    int child_status = 0;
    if (waitpid(child, &child_status, 0) != child || !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0) {
        return 1;
    }
    return 0;
}

static CFTypeRef matching_items(SecKeychainRef keychain, OSStatus *status) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        NULL, 6, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFMutableArrayRef search_list =
        CFArrayCreateMutable(NULL, 1, &kCFTypeArrayCallBacks);
    if (query == NULL || search_list == NULL) {
        release_if_present(search_list);
        release_if_present(query);
        *status = errSecAllocate;
        return NULL;
    }

    CFArrayAppendValue(search_list, keychain);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, CFSTR("io.palladin.agent"));
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query, kSecMatchSearchList, search_list);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);

    CFTypeRef results = NULL;
    *status = SecItemCopyMatching(query, &results);
    CFRelease(search_list);
    CFRelease(query);
    return results;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr,
                "Usage: development-keychain-migrator LOGIN_KEYCHAIN HELPER\n");
        return 64;
    }
    char *keychain_path = argv[1];
    char *helper_path = argv[2];
    if (keychain_path[0] != '/' || !valid_helper(helper_path)) {
        fprintf(stderr, "Error: invalid development Keychain migration input\n");
        return 1;
    }

    SecKeychainRef keychain = NULL;
    OSStatus status = SecKeychainOpen(keychain_path, &keychain);
    if (status != errSecSuccess) {
        return report_status("opening the Login Keychain", status);
    }

    CFTypeRef items = matching_items(keychain, &status);
    if (status == errSecItemNotFound) {
        CFRelease(keychain);
        printf("No existing Palladin Login Keychain items require authorization.\n");
        return 0;
    }
    if (status != errSecSuccess || items == NULL ||
        CFGetTypeID(items) != CFArrayGetTypeID()) {
        release_if_present(items);
        CFRelease(keychain);
        return report_status("finding Palladin Login Keychain items",
                             status == errSecSuccess ? errSecInternalComponent : status);
    }

    char authorize_mode[] = "--authorize-existing";
    char verify_mode[] = "--verify-existing";
    const CFIndex item_count = CFArrayGetCount((CFArrayRef)items);
    for (CFIndex index = 0; index < item_count; ++index) {
        CFTypeRef item = CFArrayGetValueAtIndex((CFArrayRef)items, index);
        char owner[OWNER_LENGTH + 1] = {0};
        const char *code = NULL;
        if (item == NULL || CFGetTypeID(item) != CFDictionaryGetTypeID() ||
            !parse_account((CFDictionaryRef)item, owner, &code)) {
            fprintf(stderr,
                    "Error: a Palladin Login Keychain item has an unsupported account identifier\n");
            CFRelease(items);
            CFRelease(keychain);
            return 1;
        }

        fprintf(stderr,
                "Migrating Palladin Login Keychain item %ld of %ld. Approve the one-time read if prompted.\n",
                (long)(index + 1), (long)item_count);
        if (run_helper(helper_path, authorize_mode, owner, (char *)code) != 0) {
            fprintf(stderr,
                    "Error: Keychain authorization was cancelled or rejected\n");
            CFRelease(items);
            CFRelease(keychain);
            return 1;
        }
        if (run_helper(helper_path, verify_mode, owner, (char *)code) != 0) {
            fprintf(stderr,
                    "Error: the migrated helper-owned Keychain item failed noninteractive verification\n");
            CFRelease(items);
            CFRelease(keychain);
            return 1;
        }
    }

    CFRelease(items);
    CFRelease(keychain);
    printf("Migrated and verified %ld Palladin Login Keychain item(s) for the stable local helper.\n",
           (long)item_count);
    return 0;
}
