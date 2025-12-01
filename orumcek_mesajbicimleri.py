# orumcek_mesajbicimleri.py
import html
import re
import unicodedata
import json
import base64
import uuid
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple

class MessageFormatter:
    """Orjinal örümcek kodunun mesaj formatını tam olarak uygulayan sınıf"""
    
    def __init__(self):
        self.replacements = self._load_replacements()
    
    def _load_replacements(self):
        """Replacements yükleme"""
        try:
            # Basit replacements yükleme
            return {}
        except Exception as e:
            print(f"Replacements yükleme hatası: {e}")
            return {}
    
    def _escape_html(self, text):
        """HTML escape işlemi"""
        if not text:
            return ""
        text = str(text)
        text = html.escape(text)
        text = text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
        return text
    
    def format_timestamp_to_tr(self, ts):
        """Timestamp'i Türkçe formata çevir"""
        try:
            if ts is None:
                return "Bilinmiyor"
            s = str(ts).strip()
            if not s:
                return "Bilinmiyor"
            
            mnum = re.fullmatch(r'\d{9,13}', s)
            if mnum:
                if len(s) >= 13:
                    val = int(s) // 1000
                else:
                    val = int(s)
                dt = datetime.fromtimestamp(val)
                aylar = {
                    1: "Ocak", 2: "Şubat", 3: "Mart", 4: "Nisan",
                    5: "Mayıs", 6: "Haziran", 7: "Temmuz", 8: "Ağustos",
                    9: "Eylül", 10: "Ekim", 11: "Kasım", 12: "Aralık"
                }
                return f"{dt.day} {aylar.get(dt.month,'')} {dt.year}"
            
            return "Bilinmiyor"
        except Exception as e:
            print(f"Timestamp format hatası: {e}")
            return "Bilinmiyor"
    
    def prepare_display_fields(self, original_base, info, user, pas):
        """Görüntü alanlarını hazırla - ORJİNAL KOD İLE AYNI"""
        def _esc_attr(val):
            return self._escape_html(str(val.strip())) if val is not None else ""

        # KATEGORİ BİLGİLERİNİ AL (FALLBACK DESTEKLİ)
        gorunen_kategoriler = info.get('gorunen_kategoriler', [])
        if not gorunen_kategoriler:
            gorunen_kategoriler = info.get('categories', [])[:8]  # Fallback
        
        kategori_listesi = info.get('kategori_listesi', [])
        if not kategori_listesi:
            kategori_listesi = info.get('categories', [])  # Fallback
            
        gorunen = gorunen_kategoriler[:8]
        gorunen_str = " • ".join(gorunen) if gorunen else "Kategori bilgisi yok"

        total_kat = len(kategori_listesi)
        shown_kat = len(gorunen)
        kalan_kategori_sayisi = max(0, total_kat - shown_kat)
        ekstra_note = f"➜ <b>{kalan_kategori_sayisi}</b> ek kategori bulunuyor." if kalan_kategori_sayisi > 0 else ""

        yerli_uyarisi = ""
        try:
            yerli_kelimeler = {"ulusal", "yerli", "turk", "trt", "turkey", "turkiye", "türkiye"}
            for k in kategori_listesi or []:
                nk = unicodedata.normalize('NFKD', k).lower()
                if any(x in nk for x in yerli_kelimeler):
                    yerli_uyarisi = "🇹🇷 Yerli Kanallar Mevcut"
                    break
        except Exception as e:
            print(f"Yerli kontrol hatası: {e}")
            yerli_uyarisi = ""

        # FORMAT BİLGİLERİ
        formats = info.get('form', [])
        if isinstance(formats, str):
            cleaned = formats.strip().lstrip('[').rstrip(']').replace("'", "").replace('"', '')
            formats = [x.strip() for x in cleaned.split(',') if x.strip()]

        icons = {'m3u8':'📺','ts':'📼','rtmp':'🔴'}
        symbols = " ".join([icons.get(f.lower(),'❔') for f in formats[:6]]) or '—'

        # REALM VE PORT BİLGİSİ
        realm = info.get('realm') or original_base
        port = info.get('port') or ""
        if realm:
            real_display = realm if realm.startswith("http") else ("http://" + realm)
            if port and (':' not in real_display.split('//')[-1]):
                real_display = f"{real_display}:{port}"
        else:
            real_display = original_base or ""
            
        # MESAJ BİLGİSİ
        raw_msg = info.get('message','') or info.get('user_info', {}).get('message', '') or ""
        if isinstance(raw_msg, str):
            raw_msg = raw_msg.replace('\\/', '/').replace('\\/', '/')
            raw_msg = raw_msg.replace('\\n', '\n').replace('\\r', '\r')
            raw_msg = re.sub(r"<p>|</p>", "", raw_msg)
            raw_msg = re.sub(r"<font[^>]*>|</font>", "", raw_msg)
            raw_msg = re.sub(r'style="[^"]*"', '', raw_msg)
            raw_msg = re.sub(r'<br\s*/?>', '\n', raw_msg)

        return {
            'safe_user': _esc_attr(user),
            'safe_pass': _esc_attr((pas[:4]+"****") if pas else "****"),
            'real_display': real_display,
            'gorunen_kategoriler_str': gorunen_str,
            'ekstra_note': ekstra_note,
            'yerli_uyarisi': yerli_uyarisi,
            'symbols': symbols,
            'safe_message': raw_msg
        }
    
    def generate_ai_comment(self, info):
        """AI yorumu oluştur - ORJİNAL KOD İLE AYNI"""
        try:
            # parse
            kanalsayi = 0
            try:
                kanalsayi = int(info.get('kanalsayisi_int') or 0)
            except Exception:
                try:
                    kanalsayi = int(re.sub(r'\D', '', str(info.get('kanalsayisi') or "0"))) or 0
                except Exception:
                    kanalsayi = 0

            feed_count = 0
            try:
                feed_count = int(info.get('feed_count_int') or 0)
            except Exception:
                try:
                    feed_count = int(re.sub(r'\D', '', str(info.get('feed_count') or "0"))) or 0
                except Exception:
                    feed_count = 0

            total_kat = 0
            try:
                total_kat = len(info.get('kategori_listesi') or [])
            except Exception:
                total_kat = 0

            days_left = info.get('days_left')

            # detected
            detected_list = None
            detected_similar = 0
            try:
                for key in ('detected_similar_list', 'detected_similars', 'detected_list', 'similar_dns_list'):
                    if key in info and isinstance(info.get(key), (list, tuple)):
                        detected_list = list(info.get(key))
                        break
                if not detected_list and isinstance(info.get('detected_similar_raw'), str):
                    raw = info.get('detected_similar_raw') or ""
                    items = [s.strip() for s in re.split(r'[\n,;]+', raw) if s.strip()]
                    if items:
                        detected_list = items
            except Exception:
                detected_list = None
                
            try:
                detected_similar = int(info.get('detected_similar_count') or info.get('detected_similar') or 0)
            except Exception:
                detected_similar = 0
                
            if isinstance(detected_list, (list, tuple)):
                try:
                    detected_similar = len(detected_list)
                except Exception:
                    pass

            # diğer alanlar
            reliability = 0.0
            try:
                reliability = float(info.get('reliability_score') or 0.0)
            except Exception:
                reliability = 0.0
                
            feed_ratio = 0.0
            try:
                feed_ratio = float(info.get('feed_ratio') or 0.0)
            except Exception:
                feed_ratio = 0.0

            ip = info.get('ip') or "Bilinmiyor"
            country = info.get('country_name') or info.get('country_code') or "Bilinmiyor"

            # yerli tespiti
            yerli_detected = False
            try:
                yerli_kelimeler = {"ulusal", "yerli", "turk", "trt", "turkey", "turkiye", "türkiye"}
                for k in (info.get('kategori_listesi') or []):
                    if not k:
                        continue
                    nk = unicodedata.normalize('NFKD', k).lower()
                    for ky in yerli_kelimeler:
                        if ky in nk:
                            yerli_detected = True
                            break
                    if yerli_detected:
                        break
            except Exception:
                yerli_detected = False

            # conn info
            mc_raw = 0
            try:
                mc_raw = int(re.sub(r'\D', '', str(info.get('max_connections') or "0"))) or 0
            except Exception:
                mc_raw = 0
                
            ac_raw = 0
            try:
                ac_raw = int(re.sub(r'\D', '', str(info.get('active_cons') or "0"))) or 0
            except Exception:
                ac_raw = 0

            # score/star
            score_val = round(float(reliability or 0.0), 2)
            stars_count = 0
            try:
                stars_count = int(round(score_val))
                stars_count = max(0, min(5, stars_count))
            except Exception:
                stars_count = 0
            stars = "⭐" * stars_count + "☆" * (5 - stars_count)
            benim_panim_line = f"Benim Panım: {stars} ({score_val}/5)"

            # içerik özeti
            cats = info.get('kategori_listesi') or []
            summary = "İçerik türü karışık/çeşitli."
            try:
                lowercats = " ".join(cats).lower()
                parts = []
                if any(x in lowercats for x in ("sport", "spor", "beinsport", "s sport")):
                    parts.append("Spor")
                if any(x in lowercats for x in ("haber", "news")):
                    parts.append("Haber")
                if any(x in lowercats for x in ("film", "movie", "vod")):
                    parts.append("Film/VOD")
                if yerli_detected:
                    parts.append("Yerli/TR")
                summary = " / ".join(parts) + " ağırlıklı." if parts else "İçerik türü karışık/çeşitli."
            except Exception:
                summary = "ℹ️ İçerik özeti yapılamadı."

            # feed line
            feed_line = "ℹ️ Kanal sayısı bilinmiyor; feed analizi sınırlı."
            if kanalsayi > 0:
                fr_pct = round(feed_ratio * 100.0, 2)
                if feed_ratio > 0.25:
                    feed_line = f"⚠️ Yüksek feed oranı: {feed_count}/{kanalsayi} ({fr_pct}%) — otomatik/re-publish olabilir."
                elif feed_count > 0:
                    feed_line = f"ℹ️ Feed kanal sayısı: {feed_count} ({fr_pct}%)."
                else:
                    feed_line = "✅ Feed kanal tespit edilmedi."

            # days
            days_note = "⏳ Abonelik süresi bilinmiyor."
            if isinstance(days_left, int):
                if days_left < 0:
                    days_note = f"❌ Süre geçmiş ({days_left} gün)."
                elif days_left < 30:
                    days_note = f"⚠️ Abonelik az kaldı: {days_left} gün."
                elif days_left < 60:
                    days_note = f"⚠️ Bitişe {days_left} gün kaldı."
                else:
                    days_note = f"✅ Abonelik süresi yeterli: {days_left} gün."

            # geo
            ccode = (info.get('country_code') or "").upper()
            latency_note = "🟡 Gecikme bölgeye göre değişir."
            if ccode in ("TR", "TRK", "TUR"):
                latency_note = "🟢 Düşük gecikme olası (yerel)."
            elif ccode in ("US", "CA", "GB", "DE", "FR", "NL"):
                latency_note = "🟡 Orta gecikme olası."
                
            geo_line = f"🌍 Lokasyon: {country} | IP: {ip} — {latency_note}"

            # reliability components
            kan_comp = round(min(1.0, kanalsayi / 1000.0) * 100, 1)
            cat_comp = round(min(1.0, total_kat / 100.0) * 100, 1)
            days_comp = 0.0
            if isinstance(days_left, int) and days_left > 0:
                days_comp = round(min(1.0, days_left / 365.0) * 100, 1)
            conn_comp = round(min(1.0, mc_raw / 10.0) * 100, 1)
            feed_pen = round(min(1.0, feed_ratio * 5.0) * 100, 1)
            reliability_line = f"🔬 Güvenilirlik bileşenleri — Kanal:{kan_comp}%, Kategori:{cat_comp}%, Süre:{days_comp}%, Conn:{conn_comp}%, FeedPen:{feed_pen}%"

            # öneriler
            actions = []
            actions.append("VPN ile test et")
            if mc_raw == 1 and ac_raw == 1:
                actions.append("Bekle veya Player Değiştir")
            elif mc_raw == 1 and ac_raw == 0:
                actions.append("Şu An İzlenmiyor Boşta")
            if feed_ratio > 0.25:
                actions.append("Feed oranı yüksek — içerik kaynağını kontrol et")
            actions_line = " • ".join(actions)

            # sadece toplam DNS sayısını göster
            detected_line = f"🔎 Tespit edilen Dns Adresleri (toplam): {detected_similar}"

            # assemble
            lines = []
            lines.append("━━━━━━━━━━━━━━━")
            lines.append("🕷️ 𝗢𝗿𝘂𝗺𝗰𝗲𝗸 𝗕𝗼𝘁 𝗬𝗼𝗿𝘂𝗺𝘂")
            lines.append(f"• {reliability_line}")
            lines.append(f"• {days_note}")
            lines.append(f"• 🧭 İçerik özeti: {summary} (Kategoriler: {total_kat}, Kanallar: {kanalsayi})")
            lines.append(f"• {feed_line}")
            lines.append(f"• {detected_line}")
            lines.append(f"• {geo_line}")
            lines.append("━━━━━━━━━━━━━━━")
            lines.append("🚀 Öneriler / Aksiyonlar")
            lines.append(actions_line)
            lines.append("━━━━━━━━━━━━━━━")
            lines.append(benim_panim_line)
            lines.append("━━━━━━━━━━━━━━━")
            return "\n".join(lines)
        except Exception as e:
            print(f"AI yorum hatası: {e}")
            return ""

     def send_to_groups(self, message_data, max_connections=1):
        """GRUP DAĞILIMI - ORJİNAL KODA TAM UYGUN"""
        results = {}
        
        # ÖNCE TÜM GRUPLARI SARI YAP
        self.reset_group_status()
        
        for chat_id in self.chat_ids:
            try:
                # ÖNCE "GÖNDERİLİYOR" DURUMUNA GETİR
                self.update_group_status(chat_id, 'gonderiliyor')

                # ✅ ORJİNAL KOD MANTIĞI:
                if max_connections > 1:
                    # ÇOKLU BAĞLANTI - SADECE ÇOKLU GRUBA GÖNDER
                    if chat_id == self.specific_group_id:
                        result = self._send_message(chat_id, message_data)
                        if result.get('ok'):
                            self.update_group_status(chat_id, 'gonderildi')
                            print(f"✅ [TELEGRAM] Çoklu bağlantı mesajı {chat_id} grubuna gönderildi")
                        else:
                            self.update_group_status(chat_id, 'hata')
                        results[chat_id] = result
                    else:
                        # Diğer gruplara HİÇ GÖNDERME
                        results[chat_id] = {'ok': True, 'skipped': 'Çoklu bağlantı - sadece çoklu gruba'}
                        print(f"⏭️ [TELEGRAM] {chat_id} atlandı (çoklu bağlantı modu)")
                else:
                    # NORMAL BAĞLANTI - SADECE NORMAL ve SCRAPER GRUPLARA GÖNDER
                    if chat_id == self.normal_group_id:
                        result = self._send_message(chat_id, message_data)
                    elif chat_id == self.scraper_group_id:
                        short_message = self._create_short_message(message_data)
                        result = self._send_message(chat_id, short_message)
                    else:
                        # Çoklu gruba GÖNDERME
                        results[chat_id] = {'ok': True, 'skipped': 'Normal bağlantı - çoklu gruba gönderilmez'}
                        continue
                    
                    if result.get('ok'):
                        self.update_group_status(chat_id, 'gonderildi')
                        print(f"✅ [TELEGRAM] Mesaj {chat_id} grubuna gönderildi")
                    else:
                        self.update_group_status(chat_id, 'hata')
                        print(f"❌ [TELEGRAM] Mesaj {chat_id} grubuna gönderilemedi: {result.get('error')}")
                    
                    results[chat_id] = result
                
                time.sleep(1)  # ✅ Telegram rate limit için 1 saniye bekle
                
            except Exception as e:
                error_msg = f"Gönderim hatası: {str(e)}"
                results[chat_id] = {'ok': False, 'error': error_msg}
                self.update_group_status(chat_id, 'hata')
                print(f"❌ [TELEGRAM] {chat_id} grubuna gönderim hatası: {e}")

        # SONUÇ ÖZETİ
        success_count = sum(1 for r in results.values() if r.get('ok') and 'skipped' not in str(r))
        print(f"📊 [TELEGRAM] Gönderim özeti: {success_count}/{len(results)} grup başarılı | Max Connections: {max_connections}")
        
        return results

    def build_error_message(self, original_base, user, pas, error_text, adaydns_text=""):
        """HATA MESAJI FORMATI - ORJİNAL KOD İLE AYNI"""
        safe_pass = (pas[:2] + "****") if pas else "****"
        incoming = (error_text or "").strip()
        
        if not incoming:
            incoming = "Bilinmeyen hata"
            
        parts = []
        parts.append("M3u Bağlantısı Hata Barındırıyor.")
        parts.append("⚠️Vpn Kullanıp Deneyniz:\n")
        
        parts.append(f"• <b>🌍 Portal:</b> {original_base}")
        parts.append(f"• <b>👤 User:</b> {user}")
        parts.append(f"• <b>🔑 Pass:</b> {safe_pass}")
        parts.append(f"• <b>Hata:</b> {incoming}")
        
        if adaydns_text:
            parts.append(f"\n{adaydns_text}")
        
        parts.append("\n💫 @Türkei Xstream İnjecktion Team")
        
        return "\n".join(parts)

    def make_ban_callback_payload(self, base: str, kategori: str = "") -> str:
        """Ban callback payload oluştur"""
        try:
            if base.startswith("http"):
                p = urlparse(base)
                host_clean = p.hostname or p.netloc
            else:
                host_clean = base
            host_clean = host_clean.split(':')[0] if host_clean else ""
            host_clean = re.sub(r'[^a-zA-Z0-9.-]', '', host_clean)
            host_short = host_clean[:20]
        except Exception:
            host_short = "unknown"

        kat_enc = ""
        if kategori:
            try:
                temp_kat = html.unescape(kategori)
                normalized_kat = unicodedata.normalize('NFKD', temp_kat).encode('ascii', 'ignore').decode('utf-8')
                safe_kat_name = re.sub(r'[^\w\s|.-]', '', normalized_kat).strip()
                safe_kat_name = safe_kat_name.replace(' ', '_').replace('|', '--')
                max_original_cat_length = 29

                if safe_kat_name:
                    original_chunk = safe_kat_name[:max_original_cat_length]
                    kat_enc = base64.urlsafe_b64encode(original_chunk.encode("utf-8")).decode("ascii")
            except Exception:
                kat_enc = ""

        if kat_enc:
            payload = f"ban:{host_short}|{kat_enc}"
        else:
            payload = f"ban:{host_short}"

        if len(payload.encode('utf-8')) > 64:
            host_very_short = host_clean[:10]
            if kat_enc:
                max_kat_enc_len = 64 - len(f"ban:{host_very_short}|".encode('utf-8'))
                if max_kat_enc_len > 0:
                    payload = f"ban:{host_very_short}|{kat_enc[:max_kat_enc_len]}"
                else:
                    payload = f"ban:{host_very_short}"
            else:
                payload = f"ban:{host_very_short}"
                
        return payload

    def make_deep_search_callback_payload(self, base: str, user: str, pas: str, found_dns: str = None) -> str:
        """Deep search callback payload oluştur"""
        try:
            if base.startswith("http"):
                p = urlparse(base)
                base_clean = p.hostname or p.netloc
            else:
                base_clean = base
            base_clean = base_clean.split(':')[0] if base_clean else ""
            base_clean = re.sub(r'[^a-zA-Z0-9.-]', '', base_clean)
        except Exception:
            base_clean = "unknown"

        base_short = base_clean[:10]
        storage_key = str(uuid.uuid4())[:8]
        
        payload = f"ds:{base_short}|{storage_key}"
        return payload

# Global instance
message_formatter = MessageFormatter()