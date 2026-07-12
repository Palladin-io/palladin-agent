import Foundation
import LocalAuthentication
import Security

private let service = "io.palladin.runtime.spike.synthetic"
private let account = "agent-identity"
private let syntheticIdentity = Data("synthetic-agent-identity-not-production".utf8)
private let useDataProtectionKeychain = ProcessInfo.processInfo.environment["PALLADIN_SPIKE_DATA_PROTECTION"] != "false"

private enum Mode: String {
    case write
    case read
    case attack
    case delete
}

private func baseQuery(accessGroup: String?) -> [CFString: Any] {
    var query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
    ]

    if useDataProtectionKeychain {
        query[kSecUseDataProtectionKeychain] = true
    }

    if let accessGroup {
        query[kSecAttrAccessGroup] = accessGroup
    }

    return query
}

private func write(accessGroup: String?, userPresence: Bool) -> OSStatus {
    SecItemDelete(baseQuery(accessGroup: accessGroup) as CFDictionary)
    var query = baseQuery(accessGroup: accessGroup)
    query[kSecValueData] = syntheticIdentity

    if userPresence {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &error
        ) else {
            return errSecParam
        }
        query[kSecAttrAccessControl] = control
    } else {
        query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }

    return SecItemAdd(query as CFDictionary, nil)
}

private func read(accessGroup: String?, allowAuthenticationUI: Bool = true) -> OSStatus {
    var query = baseQuery(accessGroup: accessGroup)
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitOne
    if !allowAuthenticationUI {
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext] = context
    }

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data else {
        return status
    }

    return data == syntheticIdentity ? errSecSuccess : errSecDecode
}

private func statusName(_ status: OSStatus) -> String {
    switch status {
    case errSecSuccess: return "success"
    case errSecItemNotFound: return "item-not-found"
    case errSecMissingEntitlement: return "missing-entitlement"
    case errSecAuthFailed: return "auth-failed"
    case errSecInteractionNotAllowed: return "interaction-not-allowed"
    default: return "osstatus-\(status)"
    }
}

guard CommandLine.arguments.count >= 2, let mode = Mode(rawValue: CommandLine.arguments[1]) else {
    FileHandle.standardError.write(Data("usage: keychain-spike <write|read|attack|delete> [--user-presence]\n".utf8))
    exit(64)
}

let accessGroup = ProcessInfo.processInfo.environment["PALLADIN_SPIKE_ACCESS_GROUP"]
let userPresence = CommandLine.arguments.contains("--user-presence")

switch mode {
case .write:
    let status = write(accessGroup: accessGroup, userPresence: userPresence)
    print("operation=write status=\(statusName(status))")
    exit(status == errSecSuccess ? 0 : 1)
case .read:
    let status = read(accessGroup: accessGroup)
    print("operation=read status=\(statusName(status))")
    exit(status == errSecSuccess ? 0 : 1)
case .attack:
    let status = read(accessGroup: accessGroup, allowAuthenticationUI: false)
    if status == errSecSuccess {
        print("result=NOT_ISOLATED invoked-binary-read=success")
        exit(10)
    }
    print("result=ISOLATED attacker-read=\(statusName(status))")
    let denied = [errSecItemNotFound, errSecMissingEntitlement, errSecAuthFailed, errSecInteractionNotAllowed]
    exit(denied.contains(status) ? 0 : 1)
case .delete:
    let status = SecItemDelete(baseQuery(accessGroup: accessGroup) as CFDictionary)
    print("operation=delete status=\(statusName(status))")
    exit(status == errSecSuccess || status == errSecItemNotFound ? 0 : 1)
}
