import Foundation
import LocalAuthentication
import Security

guard CommandLine.arguments.count == 4 else {
    FileHandle.standardError.write(Data("usage: untrusted-dpk-probe ACCESS_GROUP SERVICE ACCOUNT\n".utf8))
    exit(64)
}

let context = LAContext()
context.interactionNotAllowed = true

let query: [CFString: Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecAttrAccessGroup: CommandLine.arguments[1],
    kSecAttrService: CommandLine.arguments[2],
    kSecAttrAccount: CommandLine.arguments[3],
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
    FileHandle.standardError.write(Data("unexpected Security.framework status: \(status)\n".utf8))
    exit(1)
}

print("Untrusted Data Protection Keychain query was denied.")
