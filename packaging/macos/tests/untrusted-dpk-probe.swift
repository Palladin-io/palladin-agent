import Foundation
import LocalAuthentication
import Security

guard CommandLine.arguments.count >= 4 else {
    FileHandle.standardError.write(Data("usage: untrusted-dpk-probe ACCESS_GROUP SERVICE ACCOUNT [ACCOUNT ...]\n".utf8))
    exit(64)
}

let context = LAContext()
context.interactionNotAllowed = true

for account in CommandLine.arguments.dropFirst(3) {
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrAccessGroup: CommandLine.arguments[1],
        kSecAttrService: CommandLine.arguments[2],
        kSecAttrAccount: account,
        kSecUseDataProtectionKeychain: true,
        kSecUseAuthenticationContext: context,
        kSecReturnData: true,
        kSecMatchLimit: kSecMatchLimitOne,
    ]

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecSuccess {
        FileHandle.standardError.write(Data("untrusted process unexpectedly read a native identity slot\n".utf8))
        exit(1)
    }

    guard status == errSecMissingEntitlement || status == errSecItemNotFound else {
        FileHandle.standardError.write(Data("unexpected Security.framework denial status\n".utf8))
        exit(1)
    }
}

print("All untrusted Data Protection Keychain queries were denied.")
