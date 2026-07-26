#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$Force,
    [ValidateSet('system', 'en', 'es', 'de', 'fr', 'ja', 'ko', 'it', 'nl', 'pl', 'sv', 'pt-BR', 'zh-Hans', 'zh-Hant')]
    [string]$Language = 'system'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stateDir = Join-Path $env:LOCALAPPDATA 'RatelMesh'
$marker = Join-Path $stateDir 'geographic-privacy-v1.acknowledged'
if ((-not $Force) -and (Test-Path -LiteralPath $marker -PathType Leaf)) { exit 0 }

Add-Type -AssemblyName PresentationFramework

function Resolve-RatelMeshLanguage {
    param([string]$Requested)
    if ($Requested -ne 'system') { return $Requested }
    $culture = [Globalization.CultureInfo]::CurrentUICulture.Name
    if ($culture -match '^pt-BR') { return 'pt-BR' }
    if ($culture -match '^zh-(Hant|TW|HK|MO)') { return 'zh-Hant' }
    if ($culture -match '^zh') { return 'zh-Hans' }
    $base = $culture.Split('-')[0]
    if ($base -in @('en', 'es', 'de', 'fr', 'ja', 'ko', 'it', 'nl', 'pl', 'sv')) { return $base }
    return 'en'
}

$copy = @{
    'en' = @(
        'RatelMesh - Geographic privacy',
        "An exit device changes your public IP address, but it does not replace Windows location services.`n`nReview these settings if you do not want websites or apps to receive your physical location:`n`n• Windows Settings > Privacy & security > Location`n• Browser site settings > Location: Block or Ask`n• Browser WebRTC privacy settings when required by your threat model`n• Wi-Fi/Bluetooth scanning and personalized advertising settings`n`nRatelMesh never changes these privacy permissions without your consent.`n`nOpen Windows Location settings now?"
    )
    'es' = @(
        'RatelMesh - Privacidad de ubicación',
        "Un dispositivo de salida cambia tu dirección IP pública, pero no sustituye los servicios de ubicación de Windows.`n`nRevisa estos ajustes si no quieres que sitios web o aplicaciones reciban tu ubicación física:`n`n• Configuración de Windows > Privacidad y seguridad > Ubicación`n• Ajustes del sitio en el navegador > Ubicación: Bloquear o Preguntar`n• Privacidad de WebRTC del navegador según tu modelo de riesgo`n• Búsqueda por Wi-Fi/Bluetooth y publicidad personalizada`n`nRatelMesh nunca cambia estos permisos sin tu consentimiento.`n`n¿Abrir ahora la configuración de ubicación de Windows?"
    )
    'de' = @(
        'RatelMesh - Standortschutz',
        "Ein Exit-Gerät ändert Ihre öffentliche IP-Adresse, ersetzt aber nicht die Windows-Standortdienste.`n`nPrüfen Sie diese Einstellungen, wenn Websites oder Apps Ihren physischen Standort nicht erhalten sollen:`n`n• Windows-Einstellungen > Datenschutz und Sicherheit > Standort`n• Website-Einstellungen im Browser > Standort: Blockieren oder Nachfragen`n• WebRTC-Datenschutz im Browser entsprechend Ihrem Risikomodell`n• WLAN-/Bluetooth-Suche und personalisierte Werbung`n`nRatelMesh ändert diese Berechtigungen niemals ohne Ihre Zustimmung.`n`nWindows-Standorteinstellungen jetzt öffnen?"
    )
    'fr' = @(
        'RatelMesh - Confidentialité de la localisation',
        "Un appareil de sortie modifie votre adresse IP publique, mais ne remplace pas les services de localisation Windows.`n`nVérifiez ces réglages si vous ne voulez pas que les sites ou applications reçoivent votre position physique :`n`n• Paramètres Windows > Confidentialité et sécurité > Localisation`n• Paramètres de site du navigateur > Localisation : Bloquer ou Demander`n• Confidentialité WebRTC du navigateur selon votre modèle de risque`n• Analyse Wi-Fi/Bluetooth et publicité personnalisée`n`nRatelMesh ne modifie jamais ces autorisations sans votre consentement.`n`nOuvrir maintenant les paramètres de localisation Windows ?"
    )
    'ja' = @(
        'RatelMesh - 位置情報のプライバシー',
        "出口デバイスは公開IPアドレスを変更しますが、Windowsの位置情報サービスを置き換えるものではありません。`n`nWebサイトやアプリに現在地を渡したくない場合は、次の設定を確認してください。`n`n• Windows 設定 > プライバシーとセキュリティ > 位置情報`n• ブラウザーのサイト設定 > 位置情報：ブロックまたは確認`n• 必要に応じてブラウザーのWebRTCプライバシー設定`n• Wi-Fi/Bluetoothスキャンとパーソナライズ広告`n`nRatelMeshが同意なくこれらの権限を変更することはありません。`n`nWindowsの位置情報設定を開きますか？"
    )
    'ko' = @(
        'RatelMesh - 위치 정보 보호',
        "출구 기기는 공인 IP 주소를 바꾸지만 Windows 위치 서비스를 대체하지는 않습니다.`n`n웹사이트나 앱에 실제 위치를 제공하지 않으려면 다음 설정을 확인하세요.`n`n• Windows 설정 > 개인 정보 및 보안 > 위치`n• 브라우저 사이트 설정 > 위치: 차단 또는 묻기`n• 위험 모델에 따른 브라우저 WebRTC 개인 정보 설정`n• Wi-Fi/Bluetooth 검색 및 맞춤형 광고`n`nRatelMesh는 동의 없이 이러한 권한을 변경하지 않습니다.`n`nWindows 위치 설정을 지금 여시겠습니까?"
    )
    'it' = @(
        'RatelMesh - Privacy della posizione',
        "Un dispositivo di uscita cambia l'indirizzo IP pubblico, ma non sostituisce i servizi di posizione di Windows.`n`nControlla queste impostazioni se non vuoi che siti o app ricevano la tua posizione fisica:`n`n• Impostazioni di Windows > Privacy e sicurezza > Posizione`n• Impostazioni dei siti nel browser > Posizione: Blocca o Chiedi`n• Privacy WebRTC del browser secondo il tuo modello di rischio`n• Scansione Wi-Fi/Bluetooth e pubblicità personalizzata`n`nRatelMesh non modifica mai questi permessi senza il tuo consenso.`n`nAprire ora le impostazioni di posizione di Windows?"
    )
    'nl' = @(
        'RatelMesh - Locatieprivacy',
        "Een exitapparaat wijzigt uw openbare IP-adres, maar vervangt de locatieservices van Windows niet.`n`nControleer deze instellingen als websites of apps uw fysieke locatie niet mogen ontvangen:`n`n• Windows-instellingen > Privacy en beveiliging > Locatie`n• Site-instellingen van de browser > Locatie: Blokkeren of Vragen`n• WebRTC-privacy van de browser volgens uw risicomodel`n• Wi-Fi-/Bluetooth-scans en gepersonaliseerde advertenties`n`nRatelMesh wijzigt deze machtigingen nooit zonder uw toestemming.`n`nWindows-locatie-instellingen nu openen?"
    )
    'pl' = @(
        'RatelMesh - Prywatność lokalizacji',
        "Urządzenie wyjściowe zmienia publiczny adres IP, ale nie zastępuje usług lokalizacji Windows.`n`nSprawdź te ustawienia, jeśli strony lub aplikacje nie powinny otrzymywać Twojej fizycznej lokalizacji:`n`n• Ustawienia Windows > Prywatność i zabezpieczenia > Lokalizacja`n• Ustawienia witryn w przeglądarce > Lokalizacja: Blokuj lub Pytaj`n• Prywatność WebRTC przeglądarki zgodnie z modelem ryzyka`n• Skanowanie Wi-Fi/Bluetooth i reklamy spersonalizowane`n`nRatelMesh nigdy nie zmienia tych uprawnień bez Twojej zgody.`n`nOtworzyć ustawienia lokalizacji Windows?"
    )
    'sv' = @(
        'RatelMesh - Platsintegritet',
        "En utgångsenhet ändrar din offentliga IP-adress men ersätter inte Windows platstjänster.`n`nGranska de här inställningarna om webbplatser eller appar inte ska få din fysiska plats:`n`n• Windows-inställningar > Sekretess och säkerhet > Plats`n• Webbläsarens webbplatsinställningar > Plats: Blockera eller Fråga`n• Webbläsarens WebRTC-integritet enligt din riskmodell`n• Wi-Fi-/Bluetooth-sökning och personanpassad reklam`n`nRatelMesh ändrar aldrig dessa behörigheter utan ditt samtycke.`n`nÖppna Windows platsinställningar nu?"
    )
    'pt-BR' = @(
        'RatelMesh - Privacidade de localização',
        "Um dispositivo de saída altera seu endereço IP público, mas não substitui os serviços de localização do Windows.`n`nRevise estas configurações se não quiser que sites ou aplicativos recebam sua localização física:`n`n• Configurações do Windows > Privacidade e segurança > Localização`n• Configurações de sites do navegador > Localização: Bloquear ou Perguntar`n• Privacidade WebRTC do navegador conforme seu modelo de risco`n• Busca por Wi-Fi/Bluetooth e publicidade personalizada`n`nO RatelMesh nunca altera essas permissões sem seu consentimento.`n`nAbrir agora as configurações de localização do Windows?"
    )
    'zh-Hans' = @(
        'RatelMesh - 地理位置隐私',
        "出口设备会改变公网 IP，但不会替换 Windows 定位服务得到的物理位置。`n`n如果不希望网站或应用获得实际位置，请检查：`n`n• Windows 设置 > 隐私和安全性 > 位置`n• 浏览器网站设置 > 位置信息：阻止或询问`n• 根据风险需要检查浏览器的 WebRTC 隐私设置`n• Wi-Fi/蓝牙扫描和个性化广告设置`n`nRatelMesh 不会在未经同意时修改这些隐私权限。`n`n现在打开 Windows 定位设置吗？"
    )
    'zh-Hant' = @(
        'RatelMesh - 地理位置隱私',
        "出口裝置會改變公網 IP，但不會取代 Windows 定位服務取得的實際位置。`n`n若不希望網站或應用程式取得實際位置，請檢查：`n`n• Windows 設定 > 隱私權與安全性 > 位置`n• 瀏覽器網站設定 > 位置資訊：封鎖或詢問`n• 依風險需要檢查瀏覽器的 WebRTC 隱私設定`n• Wi-Fi/藍牙掃描和個人化廣告設定`n`nRatelMesh 不會在未經同意時變更這些隱私權限。`n`n現在開啟 Windows 定位設定嗎？"
    )
}
$localized = $copy[(Resolve-RatelMeshLanguage $Language)]
$title = $localized[0]
$message = $localized[1]

$result = [Windows.MessageBox]::Show(
    $message,
    $title,
    [Windows.MessageBoxButton]::YesNoCancel,
    [Windows.MessageBoxImage]::Information
)

if ($result -eq [Windows.MessageBoxResult]::Yes) {
    Start-Process 'ms-settings:privacy-location'
}
if ($result -ne [Windows.MessageBoxResult]::Cancel) {
    New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    New-Item -ItemType File -Path $marker -Force | Out-Null
}
