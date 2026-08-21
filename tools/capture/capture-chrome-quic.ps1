#Requires -Version 5.1
<#
    capture-chrome-quic.ps1 - Chrome'un HTTP/3 kimligini diske doker.

    NE TOPLUYOR

      1. Chrome'un ilk QUIC Initial datagramlarinin HAM byte'lari.
         Initial paketi iyi bilinen sabit bir salt + DCID ile korunur, yani
         cozmek icin anahtar GEREKMEZ. Bu tek hex blogunun icinde:
           - QUIC surumu, DCID/SCID uzunluklari ve degerleri, token
           - frame sirasi ve padding stratejisi
           - CRYPTO frame'deki TLS ClientHello (cipher'lar, GREASE, key share)
           - ClientHello icindeki QUIC transport parameters (ext 0x0039)
         Yani JA4(q) dahil QUIC katmaninin tamami.

      2. Chrome net-log'undan HTTP/3 SETTINGS, gonderilen header sirasi,
         transport parameters ve surum pazarligi (semantik dogrulama).

      3. SSLKEYLOGFILE + pcapng: Handshake ve 1-RTT paketleri de sonradan
         cozulebilsin diye.

      4. Bonus: TCP/443'e giden ilk SYN - TCP/IP katmani fingerprint'i (JA4T).

    CALISTIRMA  (PowerShell'i "Yonetici olarak calistir" ile ac)

        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\capture-chrome-quic.ps1

    Kendi hedefini de eklemek istersen:

        .\capture-chrome-quic.ps1 -Target 'https://cloudflare-quic.com/','https://hedefin.com/'

    CIKTI: Masaustunde quic-capture\ klasoru + quic-capture.zip
    Geri gonderilecek dosya: quic-capture\SUMMARY.txt

    GIZLILIK: bos bir Chrome profili acilir ve sadece verdigin adreslere
    gidilir. Yine de gondermeden once SUMMARY.txt'e bir goz at.
#>

[CmdletBinding()]
param(
    [string[]] $Target      = @('https://cloudflare-quic.com/', 'https://www.google.com/'),
    [string]   $Out         = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'quic-capture'),
    [int]      $Seconds     = 25,
    [string]   $ChromePath  = '',
    [int]      $MaxInitials = 16,
    [switch]   $NoZip
)

$ErrorActionPreference = 'Continue'
$script:Warnings = New-Object System.Collections.ArrayList

function Say  { param([string]$m) Write-Host $m -ForegroundColor Gray }
function Step { param([string]$m) Write-Host ''; Write-Host "==> $m" -ForegroundColor Cyan }
function Good { param([string]$m) Write-Host "    $m" -ForegroundColor Green }
function Warn { param([string]$m) Write-Host "    ! $m" -ForegroundColor Yellow; [void]$script:Warnings.Add($m) }
function Fail { param([string]$m) Write-Host "    x $m" -ForegroundColor Red;    [void]$script:Warnings.Add($m) }

function Q { param([string]$s) return '"' + $s + '"' }

# ------------------------------------------------------------------ helpers

function ToHex {
    param([byte[]]$B, [int]$O, [int]$N)
    if ($N -le 0) { return '' }
    if ($O + $N -gt $B.Length) { $N = $B.Length - $O }
    if ($N -le 0) { return '' }
    return [BitConverter]::ToString($B, $O, $N).Replace('-', '').ToLowerInvariant()
}

function U16BE {
    param([byte[]]$B, [int]$O)
    return ([int]$B[$O] * 256) + [int]$B[$O + 1]
}

function U32 {
    param([byte[]]$B, [int]$O, [bool]$LE)
    if ($LE) { return [BitConverter]::ToUInt32($B, $O) }
    $t = New-Object byte[] 4
    $t[0] = $B[$O + 3]; $t[1] = $B[$O + 2]; $t[2] = $B[$O + 1]; $t[3] = $B[$O]
    return [BitConverter]::ToUInt32($t, 0)
}

function IPv4Str {
    param([byte[]]$B, [int]$O)
    return ('{0}.{1}.{2}.{3}' -f $B[$O], $B[$O + 1], $B[$O + 2], $B[$O + 3])
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-Chrome {
    param([string]$Hint)
    if ($Hint -and (Test-Path $Hint)) { return $Hint }
    $candidates = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Google\Chrome Beta\Application\chrome.exe",
        "$env:ProgramFiles\Google\Chrome Dev\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome SxS\Application\chrome.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    $cmd = Get-Command chrome.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return ''
}

function Find-Exe {
    param([string]$Name, [string[]]$Dirs)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($d in $Dirs) {
        $p = Join-Path $d $Name
        if (Test-Path $p) { return $p }
    }
    return ''
}

# ------------------------------------------------------------- capture side

function Get-DumpcapInterface {
    param([string]$Dumpcap)
    $guid = ''
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                 Sort-Object RouteMetric | Select-Object -First 1
        if ($route) {
            $ad = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop
            if ($ad) { $guid = $ad.InterfaceGuid }
        }
    } catch { }

    $lines = @(& $Dumpcap -D 2>$null)
    if ($lines.Count -eq 0) { return '' }
    if ($guid) {
        foreach ($l in $lines) {
            if ($l -like "*$guid*" -and $l -match '^\s*(\d+)\.') { return $Matches[1] }
        }
    }
    foreach ($l in $lines) {
        if ($l -match '^\s*(\d+)\.' -and $l -notmatch 'loopback') { return $Matches[1] }
    }
    return ''
}

function Start-Capture {
    param([string]$Dumpcap, [string]$PcapPath, [int]$Duration)

    if ($Dumpcap) {
        $iface = Get-DumpcapInterface -Dumpcap $Dumpcap
        if ($iface) {
            $line = '-i {0} -f {1} -s 0 -w {2} -a duration:{3} -q' -f `
                    $iface, (Q 'udp port 443 or tcp port 443'), (Q $PcapPath), $Duration
            Say "    dumpcap -i $iface"
            $p = Start-Process -FilePath $Dumpcap -ArgumentList $line -PassThru -WindowStyle Hidden
            Start-Sleep -Seconds 2
            if ($p -and -not $p.HasExited) { return @{ Kind = 'dumpcap'; Proc = $p } }
            Warn 'dumpcap hemen kapandi (npcap kurulu mu?) - pktmon deneniyor'
        } else {
            Warn 'dumpcap arayuzu secilemedi - pktmon deneniyor'
        }
    }

    # pktmon: Windows 10 1809+ ile hazir gelir, ek kurulum istemez.
    $etl = [IO.Path]::ChangeExtension($PcapPath, '.etl')
    & pktmon filter remove 2>&1 | Out-Null
    & pktmon filter add quiccapu -t UDP -p 443 2>&1 | Out-Null
    & pktmon filter add quiccapt -t TCP -p 443 2>&1 | Out-Null

    $started = $false
    & pktmon start --capture --pkt-size 0 --file-name $etl --file-size 512 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { $started = $true }
    if (-not $started) {
        & pktmon start -c --pkt-size 0 -f $etl -s 512 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $started = $true }
    }
    if (-not $started) { Fail 'pktmon baslatilamadi'; return $null }
    Say '    pktmon capture basladi'
    return @{ Kind = 'pktmon'; Etl = $etl; Pcap = $PcapPath }
}

function Stop-Capture {
    param($Handle)
    if (-not $Handle) { return $false }

    if ($Handle.Kind -eq 'dumpcap') {
        # dumpcap konsolsuz calisiyor, o yuzden CloseMainWindow tutmaz; dogrudan
        # sonlandir. Yakalanani diske yazmasi icin bir an ver.
        try { if (-not $Handle.Proc.HasExited) { Stop-Process -Id $Handle.Proc.Id -ErrorAction SilentlyContinue } } catch { }
        Start-Sleep -Seconds 3
        try { if (-not $Handle.Proc.HasExited) { Stop-Process -Id $Handle.Proc.Id -Force -ErrorAction SilentlyContinue } } catch { }
        Start-Sleep -Seconds 1
        return (Test-Path $script:PcapGlobal)
    }

    & pktmon stop 2>&1 | Out-Null
    & pktmon filter remove 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    & pktmon etl2pcap $Handle.Etl --out $Handle.Pcap 2>&1 | Out-Null
    if (-not (Test-Path $Handle.Pcap)) {
        & pktmon pcapng $Handle.Etl -o $Handle.Pcap 2>&1 | Out-Null
    }
    if (-not (Test-Path $Handle.Pcap)) { Fail 'pktmon .etl -> .pcapng cevrilemedi'; return $false }
    Remove-Item $Handle.Etl -Force -ErrorAction SilentlyContinue
    return $true
}

# --------------------------------------------------------- minik pcap okuru

# Bir link-layer cercevesini cozer ve ilgilendigimiz paketler icin offset
# doner. Hex'e cevirmek pahali oldugu icin burada YAPILMAZ - sadece saklamaya
# karar verdigimiz paketler hex'lenir.
function Read-Frame {
    param([byte[]]$Buf, [int]$Off, [int]$Len, [int]$LinkType)

    $p   = $Off
    $end = $Off + $Len
    $ipv = 0

    switch ($LinkType) {
        1 {
            if ($Len -lt 14) { return $null }
            $et = U16BE $Buf ($p + 12)
            $p += 14
            while ($et -eq 0x8100 -or $et -eq 0x88a8 -or $et -eq 0x9100) {
                if ($p + 4 -gt $end) { return $null }
                $et = U16BE $Buf ($p + 2)
                $p += 4
            }
            if     ($et -eq 0x0800) { $ipv = 4 }
            elseif ($et -eq 0x86dd) { $ipv = 6 }
            else { return $null }
        }
        0 {
            if ($Len -lt 4) { return $null }
            $af = U32 $Buf $p $true
            $p += 4
            if ($af -eq 2) { $ipv = 4 }
            elseif ($af -eq 23 -or $af -eq 24 -or $af -eq 28 -or $af -eq 30) { $ipv = 6 }
            else { return $null }
        }
        113 {
            if ($Len -lt 16) { return $null }
            $et = U16BE $Buf ($p + 14)
            $p += 16
            if     ($et -eq 0x0800) { $ipv = 4 }
            elseif ($et -eq 0x86dd) { $ipv = 6 }
            else { return $null }
        }
        101 { if ($Len -lt 1) { return $null }; $ipv = ($Buf[$p] -shr 4) }
        228 { $ipv = 4 }
        229 { $ipv = 6 }
        default {
            if ($Len -lt 1) { return $null }
            $v = ($Buf[$p] -shr 4)
            if ($v -eq 4 -or $v -eq 6) { $ipv = $v } else { return $null }
        }
    }

    $ipStart = $p
    if ($ipv -eq 4) {
        if ($p + 20 -gt $end) { return $null }
        $ihl = ($Buf[$p] -band 0x0f) * 4
        if ($ihl -lt 20 -or $p + $ihl -gt $end) { return $null }
        $ttl    = [int]$Buf[$p + 8]
        $proto  = [int]$Buf[$p + 9]
        $src    = IPv4Str $Buf ($p + 12)
        $dst    = IPv4Str $Buf ($p + 16)
        $totLen = U16BE $Buf ($p + 2)
        $p += $ihl
        $ipEnd = $ipStart + $totLen
        if ($totLen -eq 0 -or $ipEnd -gt $end) { $ipEnd = $end }
    } elseif ($ipv -eq 6) {
        if ($p + 40 -gt $end) { return $null }
        $ttl   = [int]$Buf[$p + 7]
        $proto = [int]$Buf[$p + 6]
        $src   = ToHex $Buf ($p + 8)  16
        $dst   = ToHex $Buf ($p + 24) 16
        $plen  = U16BE $Buf ($p + 4)
        $p += 40
        $ipEnd = $p + $plen
        if ($plen -eq 0 -or $ipEnd -gt $end) { $ipEnd = $end }
    } else {
        return $null
    }

    if ($proto -eq 17) {
        if ($p + 8 -gt $ipEnd) { return $null }
        $sport = U16BE $Buf $p
        $dport = U16BE $Buf ($p + 2)
        $ulen  = U16BE $Buf ($p + 4)
        $payOff = $p + 8
        $payLen = $ulen - 8
        if ($payLen -le 0 -or $payOff + $payLen -gt $ipEnd) { $payLen = $ipEnd - $payOff }
        if ($payLen -le 0) { return $null }
        return [pscustomobject]@{
            Proto = 'udp'; Src = $src; Dst = $dst; SPort = $sport; DPort = $dport
            TTL = $ttl; IPVer = $ipv; Off = $payOff; Len = $payLen
        }
    }

    if ($proto -eq 6) {
        if ($p + 20 -gt $ipEnd) { return $null }
        $sport = U16BE $Buf $p
        $dport = U16BE $Buf ($p + 2)
        $doff  = ([int]$Buf[$p + 12] -shr 4) * 4
        $flags = [int]$Buf[$p + 13]
        if ($doff -lt 20 -or $p + $doff -gt $ipEnd) { return $null }
        if ((($flags -band 0x02) -eq 0) -or (($flags -band 0x10) -ne 0)) { return $null }
        # JA4T icin IP + TCP basligi bir butun lazim: TTL, window, opsiyon sirasi.
        return [pscustomobject]@{
            Proto = 'tcp-syn'; Src = $src; Dst = $dst; SPort = $sport; DPort = $dport
            TTL = $ttl; IPVer = $ipv; Off = $ipStart; Len = (($p + $doff) - $ipStart)
        }
    }
    return $null
}

$script:QuicVersions = @{
    '00000001' = 'QUIC v1 (RFC 9000)'
    '6b3343cf' = 'QUIC v2 (RFC 9369)'
    '51303530' = 'gQUIC Q050'
    '51303436' = 'gQUIC Q046'
}

function Get-QuicKind {
    param([byte]$B0, [string]$VerHex)
    if (($B0 -band 0x80) -eq 0) { return '1-RTT' }
    if ($VerHex -eq '00000000') { return 'VersionNegotiation' }
    $t = ($B0 -band 0x30) -shr 4
    if ($VerHex -eq '6b3343cf') {
        switch ($t) { 0 { return 'Retry' } 1 { return 'Initial' } 2 { return '0-RTT' } 3 { return 'Handshake' } }
    }
    switch ($t) { 0 { return 'Initial' } 1 { return '0-RTT' } 2 { return 'Handshake' } 3 { return 'Retry' } }
    return 'Unknown'
}

function Read-Capture {
    param([string]$Path, [int]$MaxInitials)

    $res = [pscustomobject]@{
        Initials = New-Object System.Collections.ArrayList
        Others   = New-Object System.Collections.ArrayList
        Syns     = New-Object System.Collections.ArrayList
        Frames   = 0
        Note     = ''
    }
    if (-not (Test-Path $Path)) { $res.Note = 'pcap dosyasi yok'; return $res }

    $fi = Get-Item $Path
    if ($fi.Length -lt 32) { $res.Note = 'pcap bos'; return $res }
    if ($fi.Length -gt 500MB) { $res.Note = 'pcap cok buyuk, ayristirilmadi'; return $res }

    $b = [IO.File]::ReadAllBytes($Path)
    $magic = ToHex $b 0 4

    $records = New-Object System.Collections.ArrayList   # her biri: frame nesnesi
    $seen = @{}

    $keep = {
        param($f)
        $res.Frames++
        if ($f.Proto -eq 'tcp-syn') {
            if ($f.DPort -eq 443 -and $res.Syns.Count -lt 4) {
                [void]$res.Syns.Add([pscustomobject]@{
                    Dst = $f.Dst; DPort = $f.DPort; TTL = $f.TTL; IPVer = $f.IPVer
                    Hex = (ToHex $b $f.Off $f.Len)
                })
            }
            return
        }
        if ($f.DPort -ne 443 -or $f.Len -lt 5) { return }
        $b0 = $b[$f.Off]
        if (($b0 -band 0x80) -eq 0) { return }          # short header: ilgilenmiyoruz
        $ver  = ToHex $b ($f.Off + 1) 4
        $kind = Get-QuicKind -B0 $b0 -VerHex $ver
        $sig  = $ver + '|' + (ToHex $b $f.Off ([Math]::Min(40, $f.Len)))
        if ($seen.ContainsKey($sig)) { return }
        $seen[$sig] = $true
        if ($kind -eq 'Initial') {
            if ($res.Initials.Count -ge $MaxInitials) { return }
            [void]$res.Initials.Add([pscustomobject]@{
                Kind = $kind; Version = $ver; Dst = $f.Dst; Bytes = $f.Len
                Hex = (ToHex $b $f.Off $f.Len)
            })
        } else {
            if ($res.Others.Count -ge 4) { return }
            [void]$res.Others.Add([pscustomobject]@{
                Kind = $kind; Version = $ver; Dst = $f.Dst; Bytes = $f.Len
                Hex = (ToHex $b $f.Off ([Math]::Min(600, $f.Len)))
            })
        }
    }

    if ($magic -eq 'd4c3b2a1' -or $magic -eq '4d3cb2a1' -or $magic -eq 'a1b2c3d4' -or $magic -eq 'a1b23c4d') {
        $le = ($magic -eq 'd4c3b2a1' -or $magic -eq '4d3cb2a1')
        $link = [int](U32 $b 20 $le)
        $p = 24
        while ($p + 16 -le $b.Length) {
            $incl = [long](U32 $b ($p + 8) $le)
            if ($incl -le 0 -or $p + 16 + $incl -gt $b.Length) { break }
            $f = Read-Frame -Buf $b -Off ($p + 16) -Len ([int]$incl) -LinkType $link
            if ($f) { & $keep $f }
            $p += 16 + [int]$incl
        }
        return $res
    }

    if ($magic -ne '0a0d0d0a') { $res.Note = "taninmayan capture formati ($magic)"; return $res }

    $bom = ToHex $b 8 4
    if ($bom -eq '4d3c2b1a') { $le = $true }
    elseif ($bom -eq '1a2b3c4d') { $le = $false }
    else { $res.Note = 'pcapng byte-order magic okunamadi'; return $res }

    $links = @{}
    $ifCount = 0
    $p = 0
    while ($p + 12 -le $b.Length) {
        $bt = U32 $b $p $le
        $bl = [long](U32 $b ($p + 4) $le)
        if ($bl -lt 12 -or $p + $bl -gt $b.Length) { break }

        if ($bt -eq 1) {
            # IDB.linktype dosyanin byte sirasinda tutulan bir u16'dir.
            if ($le) { $lt = [int]$b[$p + 8] + ([int]$b[$p + 9] * 256) }
            else     { $lt = U16BE $b ($p + 8) }
            $links[$ifCount] = $lt
            $ifCount++
        } elseif ($bt -eq 6) {
            $ifid = [int](U32 $b ($p + 8) $le)
            $cap  = [long](U32 $b ($p + 20) $le)
            $lt = 1
            if ($links.ContainsKey($ifid)) { $lt = $links[$ifid] }
            if ($cap -gt 0 -and $p + 28 + $cap -le $b.Length) {
                $f = Read-Frame -Buf $b -Off ([int]($p + 28)) -Len ([int]$cap) -LinkType $lt
                if ($f) { & $keep $f }
            }
        } elseif ($bt -eq 3) {
            $orig = [long](U32 $b ($p + 8) $le)
            $cap = $bl - 16
            if ($cap -gt $orig) { $cap = $orig }
            $lt = 1
            if ($links.ContainsKey(0)) { $lt = $links[0] }
            if ($cap -gt 0 -and $p + 12 + $cap -le $b.Length) {
                $f = Read-Frame -Buf $b -Off ([int]($p + 12)) -Len ([int]$cap) -LinkType $lt
                if ($f) { & $keep $f }
            }
        }
        $p += [int]$bl
    }
    return $res
}

# ------------------------------------------------------------ net-log okuru

$script:WantedNetLog = @(
    'QUIC_SESSION',
    'QUIC_SESSION_VERSION_NEGOTIATED',
    'QUIC_SESSION_TRANSPORT_PARAMETERS_SENT',
    'QUIC_SESSION_TRANSPORT_PARAMETERS_RECEIVED',
    'QUIC_SESSION_TRANSPORT_PARAMETERS_RESUMED',
    'QUIC_SESSION_CRYPTO_FRAME_SENT',
    'HTTP3_SETTINGS_SENT',
    'HTTP3_SETTINGS_RECEIVED',
    'HTTP3_HEADERS_SENT',
    'HTTP3_HEADERS_DECODED',
    'HTTP3_PRIORITY_UPDATE_SENT',
    'HTTP3_STREAM_TYPE_SENT',
    'HTTP3_GOAWAY_RECEIVED'
)

function Read-NetLog {
    param([string]$Path, [int]$Max = 400)

    $res = [pscustomobject]@{
        Ok     = $false
        Events = New-Object System.Collections.ArrayList
        Note   = ''
    }
    if (-not (Test-Path $Path)) { $res.Note = 'netlog.json olusmadi'; return $res }

    $sr = $null
    try {
        # The constants block has to come out before any event can be named,
        # because an event carries only a numeric type id.
        #
        # It is NOT safe to look for a line that begins with "events": Chrome
        # writes the whole constants object and the opening of the events array
        # on one line, so a line-oriented search walks past it and swallows the
        # entire log. Read a bounded prefix and cut on the substring instead.
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        $cap = 32MB
        if ($fs.Length -lt $cap) { $cap = [int]$fs.Length }
        $buf = New-Object byte[] $cap
        $got = $fs.Read($buf, 0, $cap)
        $fs.Close()
        $head = [System.Text.Encoding]::UTF8.GetString($buf, 0, $got)

        $cut = $head.IndexOf('"events"')
        if ($cut -lt 0) {
            $res.Note = 'net-log icinde "events" bulunamadi (dosya bos ya da kirpilmis)'
            return $res
        }
        $json = $head.Substring(0, $cut).TrimEnd().TrimEnd(',')
        if (-not $json.EndsWith('}')) { $json = $json + '}' }

        $constants = $null
        try { $constants = (ConvertFrom-Json $json).constants } catch {
            $res.Note = "net-log sabitleri cozulemedi: $($_.Exception.Message)"
            return $res
        }
        if (-not $constants -or -not $constants.logEventTypes) {
            $res.Note = 'net-log sabitleri okundu ama logEventTypes yok'
            return $res
        }

        # Events are one per line from here on, so the rest streams. The
        # constants line itself will not parse as a single event and is skipped.
        $sr = New-Object System.IO.StreamReader($Path)

        $idToName = @{}
        $wantIds  = @{}
        foreach ($prop in $constants.logEventTypes.PSObject.Properties) {
            $id = [int]$prop.Value
            $idToName[$id] = $prop.Name
            if ($script:WantedNetLog -contains $prop.Name) { $wantIds[$id] = $true }
        }

        $kept = 0
        while ($null -ne ($line = $sr.ReadLine())) {
            if ($kept -ge $Max) { break }
            if ($line -notmatch '"type":\s*(\d+)') { continue }
            $tid = [int]$Matches[1]
            if (-not $wantIds.ContainsKey($tid)) { continue }
            $t = $line.Trim().TrimEnd(',')
            if (-not $t.StartsWith('{')) { continue }
            $ev = $null
            try { $ev = ConvertFrom-Json $t } catch { continue }
            $srcId = ''
            if ($ev.source) { $srcId = $ev.source.id }
            [void]$res.Events.Add([pscustomobject]@{
                Name   = $idToName[$tid]
                Phase  = $ev.phase
                Source = $srcId
                Params = $ev.params
            })
            $kept++
        }
        $res.Ok = $true
    } catch {
        $res.Note = "net-log okunurken hata: $($_.Exception.Message)"
    } finally {
        if ($sr) { $sr.Dispose() }
    }
    return $res
}

# ===================================================================== main

Write-Host ''
Write-Host '  chrome quic capture' -ForegroundColor Magenta
Write-Host '  --------------------------------------------------------------' -ForegroundColor DarkGray

if (-not (Test-Admin)) {
    Write-Host ''
    Write-Host '  Paket yakalamak icin YONETICI hakki gerekiyor.' -ForegroundColor Red
    Write-Host '  PowerShell''i "Yonetici olarak calistir" ile acip tekrar dene.' -ForegroundColor Red
    Write-Host ''
    exit 1
}

Step 'ortam'
$chrome = Find-Chrome -Hint $ChromePath
if (-not $chrome) { Fail 'Chrome bulunamadi. -ChromePath ile tam yolunu ver.'; exit 1 }
$chromeVer = ''
try { $chromeVer = (Get-Item $chrome).VersionInfo.ProductVersion } catch { }
Good "chrome   $chromeVer"
Say  "         $chrome"

$wsDirs  = @("$env:ProgramFiles\Wireshark", "${env:ProgramFiles(x86)}\Wireshark")
$dumpcap = Find-Exe -Name 'dumpcap.exe' -Dirs $wsDirs
$tshark  = Find-Exe -Name 'tshark.exe'  -Dirs $wsDirs
if ($dumpcap) { Good "dumpcap  $dumpcap" } else { Say '         dumpcap yok -> pktmon kullanilacak' }
if ($tshark)  { Good "tshark   $tshark" }  else { Say '         tshark yok  -> cozumleme burada yapilmayacak (sorun degil)' }

$osCaption = ''
try { $osCaption = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { }
$osVersion = [Environment]::OSVersion.Version.ToString()
$arch      = $env:PROCESSOR_ARCHITECTURE
Good "windows  $osCaption ($osVersion, $arch)"

Step 'klasorler'
if (Test-Path $Out) { Remove-Item $Out -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $Out -Force | Out-Null
$profileDir = Join-Path $env:TEMP ('quiccap-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
$pcap   = Join-Path $Out 'capture.pcapng'
$keylog = Join-Path $Out 'sslkeys.log'
$netlog = Join-Path $Out 'netlog.json'
$script:PcapGlobal = $pcap
Good $Out

Step 'paket yakalama'
$cap = Start-Capture -Dumpcap $dumpcap -PcapPath $pcap -Duration ($Seconds + 45)
if (-not $cap) { Fail 'Yakalama baslatilamadi; net-log yine de toplanacak.' }

Step 'chrome aciliyor (bos profil)'
# --origin-to-force-quic-on: Alt-Svc kesfini beklemeden ilk istegi QUIC ile
# yollatir, boylece ilk Initial paketi kesin yakalanir.
$hosts = New-Object System.Collections.ArrayList
foreach ($t in $Target) {
    try { [void]$hosts.Add(([Uri]$t).Host + ':443') } catch { }
}
$forceArg = (($hosts | Select-Object -Unique) -join ',')

$env:SSLKEYLOGFILE = $keylog

$chromeLine = @(
    '--user-data-dir=' + (Q $profileDir),
    '--no-first-run',
    '--no-default-browser-check',
    '--no-service-autorun',
    '--disable-search-engine-choice-screen',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-sync',
    '--disable-domain-reliability',
    '--metrics-recording-only',
    '--enable-quic',
    ('--origin-to-force-quic-on=' + $forceArg),
    '--log-net-log=' + (Q $netlog),
    '--net-log-capture-mode=IncludeSensitive',
    # Both, deliberately. The SSLKEYLOGFILE environment variable is the
    # documented way and is set above, but it went unwritten on the first
    # capture from a Windows 10 box; the command-line flag is honoured by the
    # same code path and does not depend on the environment reaching the child.
    '--ssl-key-log-file=' + (Q $keylog),
    '--new-window',
    (Q $Target[0])
) -join ' '

$proc = $null
try { $proc = Start-Process -FilePath $chrome -ArgumentList $chromeLine -PassThru -ErrorAction Stop } catch { }
if (-not $proc) { Fail 'Chrome baslatilamadi'; exit 1 }
Good "pid $($proc.Id)  ->  $($Target[0])"
Say  "         force-quic-on: $forceArg"

$half = [Math]::Max(6, [int]($Seconds / 2))
Start-Sleep -Seconds $half

for ($i = 1; $i -lt $Target.Count; $i++) {
    Say "    + $($Target[$i])"
    $l = '--user-data-dir=' + (Q $profileDir) + ' ' + (Q $Target[$i])
    Start-Process -FilePath $chrome -ArgumentList $l | Out-Null
    Start-Sleep -Seconds 5
}

# Ilk hedefi bir kez daha: ikinci baglanti, ticket resumption ve 0-RTT icin.
$sep = '?'
if ($Target[0].Contains('?')) { $sep = '&' }
$again = $Target[0] + $sep + 'quiccap=2'
Say "    + $again"
Start-Process -FilePath $chrome -ArgumentList ('--user-data-dir=' + (Q $profileDir) + ' ' + (Q $again)) | Out-Null
Start-Sleep -Seconds ([Math]::Max(8, $Seconds - $half))

Step 'chrome kapatiliyor (net-log yazilsin diye nazikce)'
# SADECE bu script'in actigi gecici profili kapat. Kullanicinin kendi Chrome
# pencerelerine dokunmuyoruz - o yuzden filtre komut satirindaki profil
# klasoru, "chrome.exe" adi degil.
function Get-CapturePids {
    param([string]$Dir)
    $out = @()
    try {
        $out = @(Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" -ErrorAction Stop |
                 Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Dir) } |
                 Select-Object -ExpandProperty ProcessId)
    } catch { }
    return $out
}

$capturePids = Get-CapturePids -Dir $profileDir
Say "         kapatilacak pid: $($capturePids -join ', ')"
foreach ($cpid in $capturePids) {
    $pp = Get-Process -Id $cpid -ErrorAction SilentlyContinue
    if ($pp -and $pp.MainWindowHandle -ne [IntPtr]::Zero) {
        try { [void]$pp.CloseMainWindow() } catch { }
    }
}
Start-Sleep -Seconds 6

# Kalan varsa (renderer/gpu alt surecleri) zorla kapat - yine sadece bizimkiler.
foreach ($cpid in (Get-CapturePids -Dir $profileDir)) {
    Stop-Process -Id $cpid -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 3
Remove-Item Env:\SSLKEYLOGFILE -ErrorAction SilentlyContinue

Step 'paket yakalama durduruluyor'
[void](Stop-Capture -Handle $cap)
if (Test-Path $pcap) { Good ('capture.pcapng  {0:N0} byte' -f (Get-Item $pcap).Length) }
else { Warn 'capture.pcapng olusmadi' }

# ------------------------------------------------------------------- analiz

Step 'analiz'
$capData = Read-Capture -Path $pcap -MaxInitials $MaxInitials
if ($capData.Note) { Warn $capData.Note }
Good ("{0} cerceve  |  {1} Initial  |  {2} diger long-header  |  {3} TCP SYN" -f `
      $capData.Frames, $capData.Initials.Count, $capData.Others.Count, $capData.Syns.Count)

$net = Read-NetLog -Path $netlog -Max 400
if ($net.Ok) { Good "$($net.Events.Count) net-log olayi" } elseif ($net.Note) { Warn $net.Note }

if ($tshark -and (Test-Path $pcap)) {
    Step 'tshark cozumlemesi'
    $ko = "tls.keylog_file:$keylog"
    try {
        & $tshark -r $pcap -o $ko -Y 'http3' -V -c 400 2>$null |
            Out-File (Join-Path $Out 'tshark-http3.txt') -Encoding utf8
        Good 'tshark-http3.txt'
    } catch { Warn "tshark http3: $($_.Exception.Message)" }
    try {
        & $tshark -r $pcap -o $ko -Y 'quic' -V -c 60 2>$null |
            Out-File (Join-Path $Out 'tshark-quic.txt') -Encoding utf8
        Good 'tshark-quic.txt'
    } catch { Warn "tshark quic: $($_.Exception.Message)" }
    try {
        & $tshark -r $pcap -o $ko -Y 'tls.handshake.type == 1' -T fields `
            -e frame.number -e udp.dstport -e tcp.dstport `
            -e tls.handshake.ja3 -e tls.handshake.ja3_full `
            -e tls.handshake.ja4 -e tls.handshake.ja4_r 2>$null |
            Out-File (Join-Path $Out 'tshark-ja.txt') -Encoding utf8
        Good 'tshark-ja.txt'
    } catch { Warn "tshark ja: $($_.Exception.Message)" }
}

# ------------------------------------------------------------------ summary

Step 'SUMMARY.txt'

$sum = New-Object System.Text.StringBuilder
function W  { param([string]$s) [void]$sum.AppendLine($s) }
function WH { param([string]$s)
    W ''
    W ('== ' + $s + ' ' + ('=' * [Math]::Max(3, 66 - $s.Length)))
    W ''
}

W '######################################################################'
W '#  chrome quic / http-3 capture'
W ('#  ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'))
W '######################################################################'

WH 'ortam'
W "chrome        : $chromeVer"
W "chrome path   : $chrome"
W "windows       : $osCaption"
W "os version    : $osVersion"
W "arch          : $arch"
W "targets       : $($Target -join ', ')"
W "force-quic-on : $forceArg"
if ($cap) { W "capture       : $($cap.Kind)" } else { W 'capture       : yok' }
if ((Test-Path $keylog) -and ((Get-Item $keylog).Length -gt 0)) {
    W "keylog        : var ($((Get-Item $keylog).Length) byte)"
} else {
    W 'keylog        : YOK  (Chrome SSLKEYLOGFILE yazmadi)'
}

WH 'client Initial datagramlari (ham hex, UDP payload)'
W 'NOT: yakalama makine genelindedir. Bu listede bu script in actigi Chrome in'
W 'yani sira o sirada calisan baska uygulamalarin QUIC baglantilari da olabilir.'
W 'Her kaydin SNI si cozuldugunde hangisinin hangisi oldugu belli olur.'
W ''
W 'Initial paket korumasi sabit bir salt + DCID ile yapilir, yani asagidaki'
W 'hex tek basina sunlari verir: QUIC surumu, DCID/SCID, token, frame sirasi,'
W 'padding stratejisi, CRYPTO frame icindeki ClientHello ve onun icindeki'
W 'QUIC transport parameters (extension 0x0039).'
W ''
if ($capData.Initials.Count -eq 0) {
    W '(!) Hic Initial yakalanamadi. Olasi sebepler:'
    W '    - UDP/443 (QUIC) ag tarafinda kapali; Chrome TCP e dusmustur'
    W '    - yakalama arayuzu yanlis secildi (VPN / sanal adaptor)'
    W '    - pktmon filtreleri tutmadi'
    W ''
    W '    Cozum: Wireshark kur (winget install WiresharkFoundation.Wireshark),'
    W '    npcap i da kurmayi kabul et, sonra script i tekrar calistir.'
} else {
    $n = 0
    foreach ($it in $capData.Initials) {
        $n++
        $vn = 'bilinmiyor'
        if ($script:QuicVersions.ContainsKey($it.Version)) { $vn = $script:QuicVersions[$it.Version] }
        W ("--- initial #{0}   dst={1}   version=0x{2} [{3}]   udp_payload={4} byte" -f `
           $n, $it.Dst, $it.Version, $vn, $it.Bytes)
        for ($i = 0; $i -lt $it.Hex.Length; $i += 128) {
            W $it.Hex.Substring($i, [Math]::Min(128, $it.Hex.Length - $i))
        }
        W ''
    }
}

if ($capData.Others.Count -gt 0) {
    WH 'diger long-header paketleri (bas kismi)'
    foreach ($o in $capData.Others) {
        W ("--- {0}   dst={1}   version=0x{2}   {3} byte" -f $o.Kind, $o.Dst, $o.Version, $o.Bytes)
        W $o.Hex
        W ''
    }
}

WH 'TCP SYN - JA4T icin (IP + TCP basligi, hex)'
if ($capData.Syns.Count -eq 0) {
    W '(TCP/443 e giden SYN yakalanmadi)'
} else {
    foreach ($s in $capData.Syns) {
        W ("--- dst={0}:{1}   ttl={2}   ipv{3}" -f $s.Dst, $s.DPort, $s.TTL, $s.IPVer)
        W $s.Hex
        W ''
    }
}

WH 'net-log: transport parameters / HTTP-3 SETTINGS / header sirasi'
if (-not $net.Ok) {
    W "(okunamadi: $($net.Note))"
} elseif ($net.Events.Count -eq 0) {
    W '(ilgili olay bulunamadi - Chrome QUIC kullanmamis olabilir)'
} else {
    foreach ($e in $net.Events) {
        $pj = ''
        if ($null -ne $e.Params) {
            try { $pj = ($e.Params | ConvertTo-Json -Depth 8 -Compress) } catch { $pj = '<serilestirilemedi>' }
        }
        if ($pj.Length -gt 4000) { $pj = $pj.Substring(0, 4000) + ' ...[kirpildi]' }
        W ("[{0}]  src={1}  phase={2}" -f $e.Name, $e.Source, $e.Phase)
        if ($pj) { W ('    ' + $pj) }
    }
}

WH 'dosyalar'
Get-ChildItem $Out | Sort-Object Name | ForEach-Object {
    W ('{0,-22} {1,14:N0} byte' -f $_.Name, $_.Length)
}

if ($script:Warnings.Count -gt 0) {
    WH 'uyarilar'
    foreach ($w in $script:Warnings) { W "- $w" }
}

$sumPath = Join-Path $Out 'SUMMARY.txt'
[IO.File]::WriteAllText($sumPath, $sum.ToString(), (New-Object System.Text.UTF8Encoding($false)))
Good $sumPath

Remove-Item $profileDir -Recurse -Force -ErrorAction SilentlyContinue

if (-not $NoZip) {
    Step 'zip'
    $zip = "$Out.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($Out, $zip)
        Good ('{0}  ({1:N0} byte)' -f $zip, (Get-Item $zip).Length)
    } catch { Warn "zip olusturulamadi: $($_.Exception.Message)" }
}

Write-Host ''
Write-Host '  --------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host ("  Initial paketi : {0}" -f $capData.Initials.Count) -ForegroundColor White
Write-Host ("  net-log olayi  : {0}" -f $net.Events.Count)       -ForegroundColor White
Write-Host ("  TCP SYN        : {0}" -f $capData.Syns.Count)     -ForegroundColor White
Write-Host ''
Write-Host '  Bana gonderilecek dosya:' -ForegroundColor Magenta
Write-Host "     $sumPath" -ForegroundColor White
Write-Host '  (zip i de gonderebilirsen daha iyi, ama SUMMARY.txt tek basina yeter)' -ForegroundColor DarkGray
Write-Host ''
