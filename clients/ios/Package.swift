// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "RatelMeshIOSCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "RatelMeshShared", targets: ["RatelMeshShared"])],
    targets: [
        .target(name: "RatelMeshShared", path: "Shared"),
        .testTarget(name: "RatelMeshSharedTests", dependencies: ["RatelMeshShared"], path: "Tests")
    ]
)

