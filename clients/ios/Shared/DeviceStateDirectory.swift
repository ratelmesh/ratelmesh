import Foundation

enum DeviceStateDirectory {
    static func prepare(in container: URL) throws -> URL {
        let state = container.appendingPathComponent("State", isDirectory: true)
        try FileManager.default.createDirectory(
            at: state,
            withIntermediateDirectories: true
        )
        try excludeFromBackup(state)
        return state
    }

    static func excludeExistingFromBackup(in container: URL) throws {
        let state = container.appendingPathComponent("State", isDirectory: true)
        guard FileManager.default.fileExists(atPath: state.path) else { return }
        try excludeFromBackup(state)
    }

    private static func excludeFromBackup(_ input: URL) throws {
        var state = input
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try state.setResourceValues(values)
        guard try state.resourceValues(
            forKeys: [.isExcludedFromBackupKey]
        ).isExcludedFromBackup == true else {
            throw CocoaError(.fileWriteUnknown)
        }
    }
}
