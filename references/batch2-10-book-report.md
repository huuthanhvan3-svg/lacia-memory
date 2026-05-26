# BÁO CÁO 10 CUỐN — BATCH 2 (Updated)

## 📥 5 CUỐN TẢI VỀ (Networking)

| STT | Sách | Dung lượng | Trang | Tình trạng |
|-----|------|-----------|-------|-----------|
| 1 | Computer Networking: A Top-Down Approach (Kurose & Ross) 8th ed | 20MB | ~800 | ✅ Text OK |
| 2 | TCP/IP Illustrated Vol 1, 2nd ed (Stevens) | 20MB | 1,059 | ✅ **Thay bản scanned cũ = bản text đẹp** |
| 3 | TCP/IP Illustrated Vol 2 (Stevens) | 26MB | ~600 | ✅ Có sẵn |
| 4 | Data Communications and Networking 4th ed (Forouzan) | 11MB | 1,171 | ✅ Text OK |
| 5 | Computer Networks 5th ed (Tanenbaum) | 6.6MB | 962 | ✅ Text OK |
| 6 | ~~Network Security Assessment (McNab)~~ → **Penetration Testing: A Hands-On Introduction (Weidman)** | 13MB | 531 | ✅ **Thay thế!** DRM cũ không đọc được |

Vị trí lưu: `~/books/cyber-security-books/network/`

## 📚 5 CUỐN TỪ THƯ VIỆN

| STT | Sách | Dung lượng | Tình trạng |
|-----|------|-----------|-----------|
| 7 | The Web Application Hacker's Handbook 2nd Ed (Stuttard & Pinto) | 15MB | ✅ LFS fixed |
| 8 | Metasploit: The Penetration Tester's Guide (Kennedy) | 6.3MB | ✅ |
| 9 | Black Hat Python (Seitz) | 6.9MB | ✅ |
| 10 | ~~Violent Python~~ → **Violent Python (EPUB)** | 2.0MB | ✅ **Thay LFS rỗng = EPUB OCR từ Archive.org** |
| 11 | OTGv4 (OWASP Testing Guide v4) | 2.2MB | ✅ |

## 🛠 3 VẤN ĐỀ KỸ THUẬT ĐÃ XỬ LÝ

### ✅ Issue 1: Network Security Assessment (McNab) — DRM Adobe
- Bản cũ: `EBX_HANDLER` DRM, không tool nào mở được
- **Giải pháp: Thay bằng "Penetration Testing: A Hands-On Introduction to Hacking" (Georgia Weidman)**
- 531 trang, No Starch Press, text đầy đủ
- Bao phủ: information gathering → vulnerability discovery → exploitation → post-exploitation → reporting
- Phù hợp hơn cho mục tiêu bug bounty vì thiên về thực hành
- Bản DRM cũ đã move vào `network/_drm-restricted/`

### ✅ Issue 2: Violent Python — Git LFS rỗng
- Bản cũ: 132 bytes LFS pointer (toàn bộ LFS budget hết)
- **Giải pháp: Download EPUB (2MB) từ Archive.org**
- OCR quality, 270 pages, đọc được
- Lưu tại: `~/books/downloads/cybersecurity/Violent Python - TJ O'Connor.epub`

### ✅ Issue 3: Stevens TCP/IP Illustrated Vol 1 — Scanned PDF
- Bản cũ: scanned 608 trang, không extract text được
- **Giải pháp: Thay = 2nd edition (20MB, 1,059 trang, text-based)**
- Text extraction OK trên hầu hết pages
- Nội dung cập nhật hơn, có thêm IPv6, DNSSEC, etc.
