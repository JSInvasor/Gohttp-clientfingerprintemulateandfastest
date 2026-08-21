# capture-chrome-quic.ps1 — nasıl çalıştırılır

## 1. Hazırlık (opsiyonel ama tavsiye edilir)

Wireshark varsa yakalama çok daha güvenilir oluyor. Yoksa script Windows'un
kendi `pktmon`'una düşüyor — o da çalışır, sadece bazı VPN/sanal adaptörlerde
paket kaçırabiliyor.

```powershell
winget install --id WiresharkFoundation.Wireshark -e
```

Kurulum sırasında **Npcap**'i de kurmayı kabul et (kutu işaretli gelir).
Kurduktan sonra bir kez oturumu kapat/aç ki PATH otursun.

## 2. Çalıştır

PowerShell'i **"Yönetici olarak çalıştır"** ile aç:

```powershell
cd C:\Users\<sen>\Downloads       # script'i indirdiğin yer
Set-ExecutionPolicy -Scope Process Bypass -Force
.\capture-chrome-quic.ps1
```

Kendi hedefini de eklemek istersen:

```powershell
.\capture-chrome-quic.ps1 -Target 'https://cloudflare-quic.com/','https://hedefin.com/'
```

Wireshark kurmadıysan ve `pktmon` da tutmazsa, sadece net-log ile de
devam edebiliriz (transport parameters + HTTP/3 SETTINGS oradan da çıkıyor):

```powershell
.\capture-chrome-quic.ps1 -Seconds 35
```

## 3. Ne oluyor

- Boş, geçici bir Chrome profili açılır (senin profiline, geçmişine,
  çerezlerine **dokunulmaz**; kendi açık Chrome pencerelerin de kapatılmaz).
- `--origin-to-force-quic-on` ile Chrome ilk isteği doğrudan QUIC ile yollar.
- ~30 saniye trafik yakalanır, sonra o geçici profil silinir.
- Masaüstünde `quic-capture\` klasörü ve `quic-capture.zip` oluşur.

## 4. Bana gönder

```
Masaüstü\quic-capture\SUMMARY.txt
```

Tek başına yeter. Zip'i de atabilirsen (pcapng + keylog içinde) daha derin
bakabilirim ama şart değil.

## Ne çıkacak, ben ne yapacağım

`SUMMARY.txt` içindeki en kritik parça **client Initial datagramlarının ham
hex'i**. QUIC Initial paketi sabit ve herkesçe bilinen bir salt + DCID ile
korunur — yani anahtara ihtiyaç yok, o hex'i ben burada açıp şunları
çıkaracağım:

| Katman | Çıkacak bilgi |
|---|---|
| UDP/datagram | tam boy, padding stratejisi, coalescing var mı |
| QUIC long header | sürüm, DCID/SCID uzunluk + değer, token, packet number uzunluğu |
| QUIC frame | CRYPTO / PADDING / PING sırası ve yerleşimi |
| TLS ClientHello | cipher listesi, GREASE konumları, key share, uzantı sırası → **JA4 (q13...)** |
| ext 0x0039 | QUIC transport parameters: sıra + değerler (`initial_max_data`, `max_udp_payload_size`, `active_connection_id_limit`, `version_information`, GREASE param'ları...) |

`net-log` bölümünden de:

- HTTP/3 SETTINGS (id/değer + **gönderim sırası**, GREASE setting dahil)
- Kontrol / QPACK encoder / QPACK decoder stream açılış sırası
- Gönderilen HTTP/3 header sırası ve pseudo-header sırası
- Sunucudan gelen transport parameters (karşı taraf ne bekliyor)

TCP SYN bölümü de bir sonraki iş için: **JA4T**. Şu an TLS "Windows Chrome"
diyor ama SYN paketi "Linux" diyor — o çelişkiyi kapatacağız.

## Sorun çıkarsa

**"Initial paketi: 0" diyorsa** — yakalama tutmamış demektir.
Sırayla dene:

1. Wireshark + Npcap kur, tekrar çalıştır.
2. VPN açıksa kapat (yakalama yanlış adaptörü seçiyor olabilir).
3. Kurumsal ağdaysan UDP/443 kapalı olabilir; mobil hotspot ile dene.

Her durumda `SUMMARY.txt`'i yine gönder — `net-log` bölümü doluysa
transport parameters ve HTTP/3 SETTINGS oradan da çıkar, o da işimi görür.
