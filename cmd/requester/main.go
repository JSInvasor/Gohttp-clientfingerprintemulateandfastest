package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	gofire "github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest"
)

func main() {
	// Hedef URL'yi komut satırından al, yoksa varsayılan kullan
	targetURL := "https://httpbin.org"
	if len(os.Args) > 1 {
		targetURL = os.Args[1]
	}

	fmt.Printf("Hedef: %s\n", targetURL)
	fmt.Println(strings.Repeat("=", 60))

	// Safari iOS 18 tarayıcı parmak izi ile client oluştur
	// Retry: 3 deneme, 500ms başlangıç gecikmesi, 429/502/503/504 kodlarında tekrar dene
	client, err := gofire.Emulate(gofire.SafariIOS18,
		gofire.WithTimeout(15*time.Second),
		gofire.WithMaxIdleConnsPerHost(500),
		gofire.WithMaxIdleConns(5000),
		gofire.WithDNSCacheTTL(5*time.Minute),
		gofire.WithRetry(3, 500*time.Millisecond, 429, 502, 503, 504),
		gofire.WithMaxResponseBodySize(10*1024*1024), // 10MB limit
	)
	if err != nil {
		log.Fatalf("Client oluşturulamadı: %v", err)
	}
	defer client.Close()

	// ──────────────────────────────────────────────────────────
	// 1. Basit GET isteği
	// ──────────────────────────────────────────────────────────
	fmt.Println("\n[1] GET İsteği")
	fmt.Println(strings.Repeat("-", 40))

	start := time.Now()
	resp, err := client.Get(targetURL + "/get")
	if err != nil {
		log.Printf("GET hatası: %v", err)
	} else {
		body, _ := resp.Text()
		fmt.Printf("  Durum Kodu : %d\n", resp.StatusCode())
		fmt.Printf("  Boyut      : %d byte\n", len(body))
		fmt.Printf("  Süre       : %v\n", time.Since(start).Round(time.Millisecond))
		fmt.Printf("  Server     : %s\n", resp.GetHeader("Server"))
		resp.Close()
	}

	// ──────────────────────────────────────────────────────────
	// 2. POST JSON isteği
	// ──────────────────────────────────────────────────────────
	fmt.Println("\n[2] POST JSON İsteği")
	fmt.Println(strings.Repeat("-", 40))

	payload := map[string]interface{}{
		"kullanici": "gofire-test",
		"mesaj":     "Merhaba Dünya!",
		"zaman":     time.Now().Format(time.RFC3339),
	}
	jsonData, _ := json.Marshal(payload)

	start = time.Now()
	resp, err = client.PostJSON(targetURL+"/post", jsonData)
	if err != nil {
		log.Printf("POST hatası: %v", err)
	} else {
		fmt.Printf("  Durum Kodu : %d\n", resp.StatusCode())
		fmt.Printf("  Süre       : %v\n", time.Since(start).Round(time.Millisecond))

		var result map[string]interface{}
		if err := resp.JSON(&result); err == nil {
			if data, ok := result["json"]; ok {
				fmt.Printf("  Gönderilen : %v\n", data)
			}
		}
		resp.Close()
	}

	// ──────────────────────────────────────────────────────────
	// 3. POST Form (URL-encoded)
	// ──────────────────────────────────────────────────────────
	fmt.Println("\n[3] POST Form (URL-encoded)")
	fmt.Println(strings.Repeat("-", 40))

	formData := url.Values{
		"kullanici": {"gofire"},
		"sifre":     {"gizli123"},
		"hatirla":   {"true"},
	}

	start = time.Now()
	resp, err = client.PostForm(targetURL+"/post", formData)
	if err != nil {
		log.Printf("PostForm hatası: %v", err)
	} else {
		fmt.Printf("  Durum Kodu : %d\n", resp.StatusCode())
		fmt.Printf("  Süre       : %v\n", time.Since(start).Round(time.Millisecond))

		var result map[string]interface{}
		if err := resp.JSON(&result); err == nil {
			if form, ok := result["form"]; ok {
				fmt.Printf("  Form Data  : %v\n", form)
			}
		}
		resp.Close()
	}

	// ──────────────────────────────────────────────────────────
	// 4. PATCH JSON isteği
	// ──────────────────────────────────────────────────────────
	fmt.Println("\n[4] PATCH JSON İsteği")
	fmt.Println(strings.Repeat("-", 40))

	patchData := []byte(`{"alan": "güncellendi", "versiyon": 2}`)
	start = time.Now()
	resp, err = client.PatchJSON(targetURL+"/patch", patchData)
	if err != nil {
		log.Printf("PATCH hatası: %v", err)
	} else {
		fmt.Printf("  Durum Kodu : %d\n", resp.StatusCode())
		fmt.Printf("  Süre       : %v\n", time.Since(start).Round(time.Millisecond))
		resp.Close()
	}

	// ──────────────────────────────────────────────────────────
	// 5. Özel header'lar ile Builder Pattern kullanımı
	// ──────────────────────────────────────────────────────────
	fmt.Println("\n[5] Builder Pattern - Özel Header'lar")
	fmt.Println(strings.Repeat("-", 40))

	start = time.Now()
	resp, err = client.BuildRequest().
		Method("GET").
		URL(targetURL + "/headers").
		Header("X-Custom-Header", "gofire-test").
		Header("Authorization", "Bearer test-token-12345").
		Send()
	if err != nil {
		log.Printf("Builder hatası: %v", err)
	} else {
		fmt.Printf("  Durum Kodu : %d\n", resp.StatusCode())
		fmt.Printf("  Süre       : %v\n", time.Since(start).Round(time.Millisecond))

		var result map[string]interface{}
		if err := resp.JSON(&result); err == nil {
			if headers, ok := result["headers"].(map[string]interface{}); ok {
				fmt.Println("  Gönderilen Header'lar:")
				fmt.Printf("    User-Agent : %v\n", headers["User-Agent"])
				fmt.Printf("    X-Custom   : %v\n", headers["X-Custom-Header"])
			}
		}
		resp.Close()
	}

	// ──────────────────────────────────────────────────────────
	// 6. PUT isteği
	// ──────────────────────────────────────────────────────────
	fmt.Println("\n[6] PUT İsteği")
	fmt.Println(strings.Repeat("-", 40))

	updateData := []byte(`{"durum": "güncellendi", "id": 42}`)
	start = time.Now()
	resp, err = client.Put(targetURL+"/put", updateData, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		log.Printf("PUT hatası: %v", err)
	} else {
		fmt.Printf("  Durum Kodu : %d\n", resp.StatusCode())
		fmt.Printf("  Süre       : %v\n", time.Since(start).Round(time.Millisecond))
		resp.Close()
	}

	// ──────────────────────────────────────────────────────────
	// 7. DELETE isteği
	// ──────────────────────────────────────────────────────────
	fmt.Println("\n[7] DELETE İsteği")
	fmt.Println(strings.Repeat("-", 40))

	start = time.Now()
	resp, err = client.Delete(targetURL + "/delete")
	if err != nil {
		log.Printf("DELETE hatası: %v", err)
	} else {
		fmt.Printf("  Durum Kodu : %d\n", resp.StatusCode())
		fmt.Printf("  Süre       : %v\n", time.Since(start).Round(time.Millisecond))
		resp.Close()
	}

	// ──────────────────────────────────────────────────────────
	// 8. Cookie yönetimi
	// ──────────────────────────────────────────────────────────
	fmt.Println("\n[8] Cookie Yönetimi")
	fmt.Println(strings.Repeat("-", 40))

	resp, err = client.Get(targetURL + "/cookies/set?session=abc123&lang=tr")
	if err != nil {
		log.Printf("Cookie set hatası: %v", err)
	} else {
		resp.Close()
		cookies, err := client.GetCookies(targetURL)
		if err == nil {
			fmt.Printf("  Kayıtlı cookie sayısı: %d\n", len(cookies))
			for _, c := range cookies {
				fmt.Printf("    %s = %s\n", c.Name, c.Value)
			}
		}
	}

	// ──────────────────────────────────────────────────────────
	// 9. Pipeline - Yüksek performanslı çoklu istek + Latency istatistikleri
	// ──────────────────────────────────────────────────────────
	fmt.Println("\n[9] Pipeline - Yüksek Performanslı Çoklu İstek")
	fmt.Println(strings.Repeat("-", 40))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("  Bağlantılar ısınıyor...")
	_ = client.PreConnect(ctx, targetURL+"/get", 5)

	pipeline := client.NewPipeline(100)
	defer pipeline.Close()

	fmt.Println("  200 istek gönderiliyor...")
	result := pipeline.Spray(ctx, "GET", targetURL+"/get", 200)

	fmt.Printf("\n  Sonuçlar:\n")
	fmt.Printf("    Toplam      : %d istek\n", result.Total)
	fmt.Printf("    Başarılı    : %d\n", result.Success)
	fmt.Printf("    Başarısız   : %d\n", result.Failed)
	fmt.Printf("    Süre        : %v\n", result.Duration.Round(time.Millisecond))
	fmt.Printf("    RPS         : %.0f istek/saniye\n", result.RPS)
	fmt.Printf("    Ort. Latency: %v\n", result.AvgLatency.Round(time.Millisecond))
	fmt.Printf("    Min Latency : %v\n", result.MinLatency.Round(time.Millisecond))
	fmt.Printf("    Max Latency : %v\n", result.MaxLatency.Round(time.Millisecond))
	fmt.Printf("    Bağlantı    : %d aktif\n", client.ActiveConnections())

	// ──────────────────────────────────────────────────────────
	// 10. Context ile zaman aşımı kontrolü
	// ──────────────────────────────────────────────────────────
	fmt.Println("\n[10] Context ile Zaman Aşımı")
	fmt.Println(strings.Repeat("-", 40))

	shortCtx, shortCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shortCancel()

	start = time.Now()
	resp, err = client.DoWithContext(shortCtx, "GET", targetURL+"/delay/1", nil, nil)
	if err != nil {
		fmt.Printf("  Hata: %v (süre: %v)\n", err, time.Since(start).Round(time.Millisecond))
	} else {
		fmt.Printf("  Durum Kodu : %d\n", resp.StatusCode())
		fmt.Printf("  Süre       : %v\n", time.Since(start).Round(time.Millisecond))
		resp.Close()
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Tüm istekler tamamlandı!")
}
