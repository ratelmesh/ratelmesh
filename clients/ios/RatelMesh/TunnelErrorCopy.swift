import Foundation

enum TunnelErrorCopy {
    static func message(for code: TunnelErrorCode, language: ProductLanguage) -> String {
        let copy = source(for: code)
        return language.localized(copy.english, chineseFallback: copy.chinese)
    }

    static func source(for code: TunnelErrorCode) -> (english: String, chinese: String) {
        switch code {
        case .configurationMissing:
            ("Save your RatelMesh connection settings first.", "请先保存 RatelMesh 连接设置。")
        case .appGroupUnavailable:
            ("RatelMesh cannot access its secure shared container.", "RatelMesh 无法访问安全共享容器。")
        case .configurationInvalid:
            ("The coordinator address is invalid.", "协调器地址无效。")
        case .configurationInsecure:
            ("The coordinator must use HTTPS.", "协调器必须使用 HTTPS。")
        case .authenticationKeyMissing:
            ("Enter an enrollment key.", "请输入入网码。")
        case .hostnameInvalid:
            ("The device name may contain letters, numbers and hyphens, up to 63 characters.", "设备名只能包含字母、数字和连字符，最长 63 个字符。")
        case .configurationUnreadable:
            ("The saved connection settings cannot be read. Configure RatelMesh again.", "无法读取已保存的连接设置，请重新配置 RatelMesh。")
        case .configurationTimeout:
            ("RatelMesh timed out while waiting for a tunnel configuration.", "RatelMesh 等待隧道配置超时。")
        case .configurationVersionMismatch:
            ("The tunnel configuration changed before it could be applied. Try again.", "隧道配置在应用前发生变化，请重试。")
        case .tunnelConfigurationInactive:
            ("The control core has not produced an active tunnel configuration.", "控制核心尚未生成有效隧道配置。")
        case .tunnelConfigurationIncomplete:
            ("The tunnel configuration is missing required interface settings.", "隧道配置缺少必要的接口设置。")
        case .tunnelConfigurationMalformed:
            ("The tunnel configuration contains an invalid field or route.", "隧道配置包含无效字段或路由。")
        case .wireGuardDescriptorUnavailable:
            ("RatelMesh could not access the system tunnel interface.", "RatelMesh 无法访问系统隧道接口。")
        case .wireGuardInvalidState:
            ("The secure tunnel is in an invalid state. Disconnect and try again.", "安全隧道状态异常，请断开后重试。")
        case .wireGuardDNSResolutionFailed:
            ("A tunnel endpoint could not be resolved. Check DNS and try again.", "无法解析隧道端点，请检查 DNS 后重试。")
        case .networkSettingsRejected:
            ("iOS rejected the tunnel network settings. Disconnect and try again.", "iOS 拒绝了隧道网络设置，请断开后重试。")
        case .wireGuardBackendStartFailed:
            ("The secure tunnel engine could not start. Try again.", "安全隧道引擎无法启动，请重试。")
        case .tunnelCancelled:
            ("Tunnel startup was cancelled.", "隧道启动已取消。")
        case .tunnelAlreadyActive:
            ("The tunnel is already starting, running or stopping. Try again shortly.", "隧道正在启动、运行或关闭，请稍后重试。")
        case .tunnelForcedTeardown:
            ("The tunnel took too long to stop and iOS was asked to close it.", "隧道关闭超时，已请求 iOS 强制停止。")
        case .invalidProviderMessage:
            ("RatelMesh sent an invalid request to the tunnel.", "RatelMesh 向隧道发送了无效请求。")
        case .invalidExit:
            ("The selected exit device is invalid.", "所选出口设备无效。")
        case .unsupportedProviderAction:
            ("This tunnel action is not supported.", "不支持此隧道操作。")
        case .exitSelectionFailed:
            ("RatelMesh could not switch to the selected exit device. Check the selection and try again.", "RatelMesh 无法切换到所选出口设备，请检查选择后重试。")
        case .vpnProfileUnavailable:
            ("The RatelMesh VPN profile is not installed or enabled.", "RatelMesh VPN 配置尚未安装或启用。")
        case .keychainUnavailable:
            ("RatelMesh cannot access the saved connection settings in Keychain.", "RatelMesh 无法访问钥匙串中的连接设置。")
        case .controlCoreStartFailed:
            ("The RatelMesh control core could not start. Try again.", "RatelMesh 控制核心无法启动，请重试。")
        case .unknownProviderError:
            ("RatelMesh could not complete the operation. Try again.", "RatelMesh 无法完成操作，请重试。")
        }
    }
}
