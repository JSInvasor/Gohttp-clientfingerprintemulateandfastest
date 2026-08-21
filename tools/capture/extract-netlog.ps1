#Requires -Version 5.1
<#
    extract-netlog.ps1 - Chrome net-log'undan HTTP/3 ve QUIC olaylarini cikarir.

    Zaten diskinde duran bir netlog.json uzerinde calisir; yeniden yakalama
    GEREKMEZ. Yonetici hakki da gerekmez.

        .\extract-netlog.ps1
        .\extract-netlog.ps1 -Path 'C:\Users\HP\Desktop\quic-capture\netlog.json'

    Cikti: ayni klasorde NETLOG-H3.txt

    Neyi cikariyor
      - HTTP3_SETTINGS_SENT / RECEIVED   (id, deger ve GONDERIM SIRASI)
      - HTTP3_HEADERS_SENT               (gonderilen header sirasi)
      - HTTP3_STREAM_TYPE_SENT           (kontrol / QPACK stream acilis sirasi)
      - QUIC_SESSION_TRANSPORT_PARAMETERS_SENT / RECEIVED
      - QUIC_SESSION_VERSION_NEGOTIATED

    Iki varsayimdan da vazgecildi
      Bir onceki surum iki sey varsayiyordu ve ikisi de tutmadi: constants
      blogunu metinden kesip JSON olarak ayristirmak (icinde baska "events"
      anahtarlari var, kesme yanlis yere dusuyor) ve olaylarin satir basina bir
      tane yazildigi (dosyanin tamami tek satir olabiliyor).

      Bu surum satir yapisina hic bakmiyor: events dizisini bulup icindeki JSON
      nesnelerini suslu parantez derinligiyle sayarak ayiriyor. Bir sey yine de
      eslesmezse SEBEBI ciktinin basina yaziyor - hangi asamada, kac tanimla,
      hangi isimler bulunamadi.
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

$diag = New-Object System.Collections.ArrayList
function D { param([string]$m) [void]$diag.Add($m); Write-Host "    $m" -ForegroundColor Gray }

Write-Host ''
Write-Host "  netlog : $Path" -ForegroundColor Cyan
Write-Host '  (buyuk bir dosyada yarim dakika surebilir)' -ForegroundColor DarkGray
$size = (Get-Item $Path).Length
D ("dosya boyutu    : {0:N0} byte" -f $size)

$text = [IO.File]::ReadAllText($Path)
D ("okunan karakter : {0:N0}" -f $text.Length)
D ("satir sayisi    : {0:N0}" -f ($text.Split("`n").Count))

# --- 1. logEventTypes -----------------------------------------------------
#
# Duz bir "AD":sayi eslemesi. Sadece bu lazim; constants'in geri kalani hic
# ayristirilmiyor.

$m = [regex]::Match($text, '"logEventTypes"\s*:\s*\{')
if (-not $m.Success) {
    D 'x logEventTypes bulunamadi - bu dosya bir net-log gibi gorunmuyor'
    [IO.File]::WriteAllText($Out, ($diag -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    exit 1
}
$from  = $m.Index + $m.Length
$close = $text.IndexOf('}', $from)
if ($close -lt 0) {
    D 'x logEventTypes blogu kapanmiyor'
    [IO.File]::WriteAllText($Out, ($diag -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    exit 1
}
$block = $text.Substring($from, $close - $from)

$idToName = @{}
$nameToId = @{}
foreach ($mm in [regex]::Matches($block, '"([A-Za-z0-9_]+)"\s*:\s*(\d+)')) {
    $nm = $mm.Groups[1].Value
    $id = [int]$mm.Groups[2].Value
    $idToName[$id] = $nm
    $nameToId[$nm] = $id
}
D ("olay turu tanimi: {0}" -f $idToName.Count)

$wantIds = @{}
$missing = New-Object System.Collections.ArrayList
foreach ($w in $wanted) {
    if ($nameToId.ContainsKey($w)) { $wantIds[$nameToId[$w]] = $true }
    else { [void]$missing.Add($w) }
}
D ("aradigimiz tur  : {0} bulundu, {1} bulunamadi" -f $wantIds.Count, $missing.Count)
if ($missing.Count -gt 0) { D ("bulunamayanlar  : " + ($missing -join ', ')) }

# Bu Chrome'da gercekten hangi H3/QUIC turleri tanimli - isim degistiyse
# gorulsun diye her halukarda yaziliyor.
$h3Names = @()
foreach ($k in $nameToId.Keys) {
    if ($k -like 'HTTP3_*' -or $k -like 'QUIC_SESSION_TRANSPORT*' -or $k -like '*VERSION_NEGOTIATED*') {
        $h3Names += $k
    }
}
$h3Names = $h3Names | Sort-Object
D ("tanimli H3/QUIC : {0} tur" -f $h3Names.Count)

# Aradiklarimiz yoksa tanimli olan her H3 turunu al.
if ($wantIds.Count -eq 0) {
    D '! aradigimiz isimlerin hicbiri yok - tanimli tum H3/QUIC turleri alinacak'
    foreach ($n in $h3Names) { $wantIds[$nameToId[$n]] = $true }
}

# --- 2. events dizisi -----------------------------------------------------

$ev = [regex]::Match($text, '"events"\s*:\s*\[')
if (-not $ev.Success) {
    D 'x "events": [ bulunamadi'
    [IO.File]::WriteAllText($Out, ($diag -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    exit 1
}
$evStart = $ev.Index + $ev.Length
D ("events dizisi   : karakter {0}" -f $evStart)

# Nesneleri suslu parantez derinligiyle ayir. Satir yapisina bakilmiyor.
# IndexOfAny ile yapisal karakterler arasinda atlanarak ilerleniyor, yoksa
# 12 MB'lik bir dosyada karakter karakter dolasmak dakikalar surerdi.
$structural = [char[]]@('{', '}', '"')
$i = $evStart
$depth = 0
$objStart = -1
$seen = 0
$kept = 0
$counts = @{}
$allCounts = @{}

$sb = New-Object System.Text.StringBuilder

while ($i -lt $text.Length) {
    $j = $text.IndexOfAny($structural, $i)
    if ($j -lt 0) { break }
    $c = $text[$j]

    if ($c -eq '"') {
        # Dizeyi atla. Kacisli tirnak, onundeki ters bolu sayisi tek ise gercek
        # bir kacistir; cift ise ters bolunun kendisi kacilmistir.
        $k = $j + 1
        while ($true) {
            $q = $text.IndexOf('"', $k)
            if ($q -lt 0) { $k = $text.Length; break }
            $b = 0
            $z = $q - 1
            while ($z -ge 0 -and $text[$z] -eq '\') { $b++; $z-- }
            if ($b % 2 -eq 0) { $k = $q; break }
            $k = $q + 1
        }
        $i = $k + 1
        continue
    }

    if ($c -eq '{') {
        if ($depth -eq 0) { $objStart = $j }
        $depth++
        $i = $j + 1
        continue
    }

    # '}'
    $depth--
    if ($depth -le 0) {
        if ($objStart -ge 0) {
            $obj = $text.Substring($objStart, $j - $objStart + 1)
            $seen++
            if ($obj -match '"type"\s*:\s*(\d+)') {
                $tid = [int]$Matches[1]
                $nm = 'type_' + $tid
                if ($idToName.ContainsKey($tid)) { $nm = $idToName[$tid] }
                if ($allCounts.ContainsKey($nm)) { $allCounts[$nm]++ } else { $allCounts[$nm] = 1 }

                if ($wantIds.ContainsKey($tid) -and $kept -lt $Max) {
                    if ($counts.ContainsKey($nm)) { $counts[$nm]++ } else { $counts[$nm] = 1 }
                    $src = ''
                    if ($obj -match '"source"\s*:\s*\{[^}]*"id"\s*:\s*(\d+)') { $src = $Matches[1] }
                    $body = $obj
                    if ($body.Length -gt 6000) { $body = $body.Substring(0, 6000) + ' ...[kirpildi]' }
                    [void]$sb.AppendLine("[$nm]  src=$src")
                    [void]$sb.AppendLine('    ' + $body)
                    $kept++
                }
            }
            $objStart = -1
        }
        $depth = 0
    }
    $i = $j + 1
}

D ("gorulen nesne   : {0}" -f $seen)
D ("alinan olay     : {0}" -f $kept)

# --- 3. yaz ---------------------------------------------------------------

$head = New-Object System.Text.StringBuilder
[void]$head.AppendLine('######################################################################')
[void]$head.AppendLine('#  net-log: HTTP/3 SETTINGS, header sirasi, transport parameters')
[void]$head.AppendLine("#  $Path")
[void]$head.AppendLine('######################################################################')
[void]$head.AppendLine('')
[void]$head.AppendLine('== tani =============================================================')
[void]$head.AppendLine('')
foreach ($d in $diag) { [void]$head.AppendLine($d) }

[void]$head.AppendLine('')
[void]$head.AppendLine('tanimli H3/QUIC olay turleri:')
foreach ($n in $h3Names) { [void]$head.AppendLine('  ' + $n) }

[void]$head.AppendLine('')
[void]$head.AppendLine('== dosyada gercekten gorulen olay turleri (ilk 40) ===================')
[void]$head.AppendLine('')
$top = $allCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 40
foreach ($e in $top) { [void]$head.AppendLine(('{0,-52} {1}' -f $e.Key, $e.Value)) }

[void]$head.AppendLine('')
[void]$head.AppendLine('== aradigimiz olaylar ===============================================')
[void]$head.AppendLine('')
if ($kept -eq 0) {
    [void]$head.AppendLine('(hicbiri eslesmedi - yukaridaki tani ve tur listesi sebebi soyluyor)')
}

[IO.File]::WriteAllText($Out, ($head.ToString() + $sb.ToString()),
    (New-Object System.Text.UTF8Encoding($false)))

Write-Host ''
foreach ($k in ($counts.Keys | Sort-Object)) {
    Write-Host ("    {0,-46} {1}" -f $k, $counts[$k]) -ForegroundColor Green
}
Write-Host ''
Write-Host '  Bana gonder:' -ForegroundColor Magenta
Write-Host "     $Out" -ForegroundColor White
Write-Host ''
