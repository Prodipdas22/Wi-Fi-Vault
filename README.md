# Wi-Fi Vault — Phase 2.1 (Scanner Fix)

This build improves Phase 2 scanning for real router labels like the supplied example.

## What changed
- Replaced browser `BarcodeDetector` dependency with `jsQR` for broader Android-browser compatibility.
- QR scanner works from live camera and from a selected photo.
- OCR preprocessing enlarges, grayscales, and increases contrast before recognition.
- OCR recognizes common labels including `WiFi SSID`, `Password`, `WPA Key`, `Wi-Fi Name`, etc.
- OCR supports a label/value split across two lines.
- Camera has a photo fallback.
- Every scanned result opens the confirmation form; the user must verify before saving.

## Important
The first QR/OCR engine download requires internet because the JS libraries are loaded from a CDN. The app shell and saved data remain local. A later offline-hardening phase can bundle the engines.

Camera access requires HTTPS. GitHub Pages provides HTTPS.

Phase 2.1 is still a prototype and stores passwords in browser localStorage without encryption. Do not use it as a production password vault.
