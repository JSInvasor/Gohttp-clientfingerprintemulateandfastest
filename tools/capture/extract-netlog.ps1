#Requires -Version 5.1
<#
    extract-netlog.ps1 - Chrome net-log'undan HTTP/3 ve QUIC olaylarini cikarir.

    Zaten diskinde duran bir netlog.json uzerinde calisir; yeniden yakalama
    GEREKMEZ.

        .\extract-netlog.ps1
        .\extract-netlog.ps1 -Path 'C:\Users\HP\Desktop\quic-capture\netlog.json'

    Cikti: ayni klasorde NETLOG-H3.txt

    Neyi cikariyor
      - HTTP3_SETTINGS_SENT / RECEIVED   (id, deger ve GONDERIM SIRASI)
      - HTTP3_HEADERS_SENT               (gonderilen header sirasi)
      - HTTP3_STREAM_TYPE_SENT           (kontrol / QPACK stream acilis sirasi)
      - QUIC_SESSION_TRANSPORT_PARAMETERS_SENT / RECEIVED
      - QUIC_SESSION_VERSION_NEGOTIATED

    Neden ayri bir script
      Bir net-log olayi turunu sadece SAYI olarak tasir; adi dosyanin basindaki
      "constants" blogundaki logEventTypes haritasindan cozulur. Bu blogu
      metinden kesip JSON olarak ayristirmak kirilgan cikti: constants icinde
      baska yerlerde de "events" gecen anahtarlar var ve kesme yanlis yerden
      oluyordu. Burada sadece logEventTypes haritasi okunuyor - o duz bir
      isim->sayi eslemesi, ve regex ile guvenle alinabiliyor.
#>

[CmdletBinding()]
param(
    [string] $Path = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'quic-capture\netlog.json'),
    [string] $Out  = '',
    [int]    $Max  = 400
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Path)) {
    Write-Host ''
    Write-Host "  netlog.json bulunamadi: $Path" -ForegroundColor Red
    Write-Host '  -Path ile tam yolunu ver.' -ForegroundColor Red
    Write-Host ''
    exit 1
}
if (-not $Out) { $Out = Join-Path (Split-Path $Path -Parent) 'NETLOG-H3.txt' }

$wanted = @(
    'HTTP3_SETTINGS_SENT',
    'HTTP3_SETTINGS_RECEIVED',
    'HTTP3_HEADERS_SENT',
    'HTTP3_HEADERS_DECODED',
    'HTTP3_STREAM_TYPE_SENT',
    'HTTP3_PRIORITY_UPDATE_SENT',
    'HTTP3_GOAWAY_RECEIVED',
    'QUIC_SESSION_TRANSPORT_PARAMETERS_SENT',
    'QUIC_SESSION_TRANSPORT_PARAMETERS_RECEIVED',
    'QUIC_SESSION_TRANSPORT_PARAMETERS_RESUMED',
    'QUIC_SESSION_VERSION_NEGOTIATED'
)

Write-Host ''
Write-Host "  netlog : $Path" -ForegroundColor Gray
Write-Host ("  boyut  : {0:N0} byte" -f (Get-Item $Path).Length) -ForegroundColor Gray

# --- 1. logEventTypes haritasi -------------------------------------------
#
# Dosyanin basindan sinirli bir on-parca okunur. logEventTypes duz bir
# "AD":sayi eslemesidir, o yuzden acilis suslu parantezinden sonraki ilk
# kapanisa kadar olan blok yeterli.

$fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
$cap = 8MB
if ($fs.Length -lt $cap) { $cap = [int]$fs.Length }
$buf = New-Object byte[] $cap
$got = $fs.Read($buf, 0, $cap)
$fs.Close()
$head = [System.Text.Encoding]::UTF8.GetString($buf, 0, $got)

$m = [regex]::Match($head, '"logEventTypes"\s*:\s*\{')
if (-not $m.Success) {
    Write-Host '  x logEventTypes bulunamadi - dosya bir net-log gibi gorunmuyor.' -ForegroundColor Red
    exit 1
}
$start = $m.Index + $m.Length
$close = $head.IndexOf('}', $start)
if ($close -lt 0) {
    Write-Host '  x logEventTypes blogu kapanmadan on-parca bitti.' -ForegroundColor Red
    exit 1
}
$block = $head.Substring($start, $close - $start)

$idToName = @{}
$wantIds  = @{}
foreach ($mm in [regex]::Matches($block, '"([A-Za-z0-9_]+)"\s*:\s*(\d+)')) {
    $nm = $mm.Groups[1].Value
    $id = [int]$mm.Groups[2].Value
    $idToName[$id] = $nm
    if ($wanted -contains $nm) { $wantIds[$id] = $true }
}
Write-Host ("  olay turu tanimi: {0}, aradigimiz: {1}" -f $idToName.Count, $wantIds.Count) -ForegroundColor Gray

if ($wantIds.Count -eq 0) {
    Write-Host '  ! Aradigimiz olay turlerinin hicbiri bu Chrome surumunde tanimli degil.' -ForegroundColor Yellow
    Write-Host '    HTTP3_ ile baslayan tum turler yazilacak.' -ForegroundColor Yellow
    foreach ($k in $idToName.Keys) {
        if ($idToName[$k] -like 'HTTP3_*' -or $idToName[$k] -like 'QUIC_SESSION_TRANSPORT*') {
            $wantIds[$k] = $true
        }
    }
}

# --- 2. olaylar ------------------------------------------------------------
#
# Buradan sonrasi satir basina bir olay. constants satirinin kendisi tek bir
# olay olarak ayristirilamayacagi icin dogal olarak eleniyor.

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('######################################################################')
[void]$sb.AppendLine('#  net-log: HTTP/3 SETTINGS, header sirasi, transport parameters')
[void]$sb.AppendLine("#  $Path")
[void]$sb.AppendLine('######################################################################')
[void]$sb.AppendLine('')

$counts = @{}
$kept = 0
$sr = New-Object System.IO.StreamReader($Path)
try {
    while ($null -ne ($line = $sr.ReadLine())) {
        if ($kept -ge $Max) { break }
        if ($line -notmatch '"type":\s*(\d+)') { continue }
        $tid = [int]$Matches[1]
        if (-not $wantIds.ContainsKey($tid)) { continue }

        $t = $line.Trim().TrimEnd(',')
        if (-not $t.StartsWith('{')) { continue }
        $ev = $null
        try { $ev = ConvertFrom-Json $t } catch { continue }

        $name = $idToName[$tid]
        if ($counts.ContainsKey($name)) { $counts[$name]++ } else { $counts[$name] = 1 }

        $src = ''
        if ($ev.source) { $src = $ev.source.id }
        $pj = ''
        if ($null -ne $ev.params) {
            try { $pj = ($ev.params | ConvertTo-Json -Depth 10 -Compress) } catch { $pj = '<?>' }
        }
        if ($pj.Length -gt 6000) { $pj = $pj.Substring(0, 6000) + ' ...[kirpildi]' }

        [void]$sb.AppendLine(("[{0}]  src={1}  phase={2}" -f $name, $src, $ev.phase))
        if ($pj) { [void]$sb.AppendLine('    ' + $pj) }
        $kept++
    }
} finally {
    $sr.Dispose()
}

[void]$sb.AppendLine('')
[void]$sb.AppendLine('== ozet =============================================================')
[void]$sb.AppendLine('')
foreach ($k in ($counts.Keys | Sort-Object)) {
    [void]$sb.AppendLine(('{0,-46} {1}' -f $k, $counts[$k]))
}

[IO.File]::WriteAllText($Out, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ''
foreach ($k in ($counts.Keys | Sort-Object)) {
    Write-Host ("    {0,-46} {1}" -f $k, $counts[$k]) -ForegroundColor Green
}
if ($kept -eq 0) {
    Write-Host '    (hicbir olay eslesmedi)' -ForegroundColor Yellow
}
Write-Host ''
Write-Host '  Bana gonder:' -ForegroundColor Magenta
Write-Host "     $Out" -ForegroundColor White
Write-Host ''
