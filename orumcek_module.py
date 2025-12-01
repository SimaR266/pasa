import os
import sys
import asyncio
import threading
import time
import json
import re
import random
import html
import unicodedata
import base64
import uuid
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from typing import Optional, Dict, List, Tuple
from threading import Lock
from pathlib import Path

import requests
import httpx
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, 
                            QPushButton, QLabel, QComboBox, QCheckBox, 
                            QGroupBox, QProgressBar, QSpinBox, QFrame, QMessageBox,
                            QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
                            QSplitter, QListWidget, QListWidgetItem, QLineEdit,
                            QFileDialog, QDialog, QDialogButtonBox,
                            QScrollArea, QAbstractItemView, QTreeWidget, QTreeWidgetItem,
                            QGridLayout, QTextBrowser, QApplication, QFormLayout,
                            QStackedWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QDateTime, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QFont, QTextCursor, QColor, QPalette, QIcon, QTextCharFormat, QPainter, QLinearGradient

# =============================================================================
# YENİ MODÜL İMPORTLARI
# =============================================================================
from orumcek_mesajbicimleri import message_formatter
from orumcek_butonmodulu import buton_yoneticisi
from orumcek_config import *  # Tüm konfigürasyon sabitleri ve fonksiyonları
from orumcek_github import gh_load_all, get_github_cache, get_github_lock  # GitHub fonksiyonları
from orumcek_gui_components import ModernSidebar, RightSidePanel, ModernProcessingPanel  # GUI bileşenleri

# =============================================================================
# APP STATE YÖNETİMİ
# =============================================================================

class AppState:
    def __init__(self):
        # ✅ TEMEL İSTATİSTİKLER - Orjinal kodla aynı
        self.gonderilen = 0
        self.total_urls = 0
        self.remaining_urls = 0
        self.specific_count = 0
        self.toplam_hata = 0
        self.engellenen_msg = 0
        self.engellenen_kat = 0
        self.yasakli_dns_count = 0
        self.kaynak_dosya_durum = "Hazır"
        
        # ✅ ADAY DNS İSTATİSTİKLERİ - Orjinal kodla aynı + GUI için ekstra
        self.aday_toplam = 0
        self.aday_kontrol_edilen = 0
        self.aday_olu = ""
        self.aday_suan = ""
        self.aday_sonuc = None
        self.aday_degisen_satir = 0
        self.tespit_edilen_benzer_sayisi = 0
        
        # ✅ ADAY DNS EKSTRA ALANLARI - GUI için gerekli
        self.aday_gecerli = 0
        self.aday_gecersiz = 0
        self.aday_durum = "Hazır"
        self.aday_bulunan = 0
        self.aday_test_edilen = 0
        self.aday_bekleyen = 0
        
        # ✅ DİNLEME İSTATİSTİKLERİ - Orjinal kodla aynı
        self.listen_started_at = None
        self.group_link_counts = {}
        self.most_link_group = None
        self.listening_group_count = 0
        self.seen_links = set()
        
        # ✅ HATA ve ENGELLEME BİLGİLERİ - Orjinal kodla aynı
        self.last_error_info = None
        self.last_blocked_dns = None
        self.last_blocked_category = None
        self.message_status = {
            -1001948263686: {'state': 'bekle', 'ts': None},
            -1002042461006: {'state': 'bekle', 'ts': None}, 
            -1001844205745: {'state': 'bekle', 'ts': None}
        }
        
        # ✅ YASAKLI LİSTELER ve VERİLER - Orjinal kodla aynı
        self.yasakli_kelimeler = []
        self.yasakli_kategoriler = []
        self.tespit_edilen = {}
        
        # ✅✅✅ BENZER DNS ALANLARI - ORJİNAL KODLA TAM UYUMLU
        self.dns_list = []  # Tespit edilen DNS listesi
        self.tespit_edilen_benzer_sayisi = 0  # Kaç DNS tespit edildi
        self.detected_dns_display = []  # Mesajda gösterilecek kısa liste
        self.group_leader_changed = 0  # Grup lideri değişen sayısı
        
        # Mesajlar için
        self.warning_messages = []
        self.current_source_file = None
        self.current_kaynak_status = "Hazır"
        
        # ✅ SEMAPHORE'lar - Orjinal kodla aynı
        self.host_semaphores = {}
        self.global_semaphore = asyncio.Semaphore(GLOBAL_MAX_CONCURRENCY)
        
        # ✅ YENİ İSTATİSTİKLER - Random işlem için gerekli
        self.duplicate_removed = 0
        self.banned_removed = 0
        self.current_processing_url = ""
        self.current_processing_stage = ""
        self.next_url = ""
        self.similar_dns_changed = 0  # Benzer DNS değişen sayısı

    def get_host_semaphore(self, host: str):
        key = host or "default"
        if key not in self.host_semaphores:
            self.host_semaphores[key] = asyncio.Semaphore(PER_HOST_CONCURRENCY)
        return self.host_semaphores[key]
    
    def add_warning(self, message: str):
        """Warning mesajı ekle"""
        try:
            if message and message not in self.warning_messages:
                self.warning_messages.append(message)
                if len(self.warning_messages) > 10:
                    self.warning_messages.pop(0)
        except:
            pass
    
    def update_detected_dns(self, dns_list: list):
        """Tespit edilen DNS'leri güncelle"""
        try:
            self.dns_list = dns_list
            self.tespit_edilen_benzer_sayisi = len(dns_list)
            
            # Mesajda gösterilecek kısa listeyi hazırla (ilk 6)
            self.detected_dns_display = []
            for i, dns in enumerate(dns_list[:6]):
                if len(dns) > 50:
                    display = dns[:47] + "..."
                else:
                    display = dns
                self.detected_dns_display.append(display)
                
        except Exception as e:
            print(f"❌ Detected DNS update error: {e}")

# =============================================================================
# URL İŞLEME FONKSİYONLARI
# =============================================================================

def clean_title(s: str) -> str:
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", s)
    s = re.sub(r'[\U00010000-\U0010FFFF]', '', s)
    s = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', s)
    return s.strip()

def extract_hostname(s: str) -> str:
    try:
        if not s:
            return ""
        s = str(s).strip()
        if s.startswith("http://") or s.startswith("https://"):
            return urlparse(s).hostname or ""
        return s.split('//')[-1].split(':')[0].split('/')[0].strip()
    except Exception:
        try:
            return str(s).split('//')[-1].split(':')[0].split('/')[0].strip()
        except Exception:
            return ""

class URLProcessor:
    @staticmethod
    def normalize_and_parse(url: str) -> tuple[str, str, int, dict]:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        
        p = urlparse(url)
        scheme = p.scheme or "http"
        host = p.hostname or p.netloc or ""
        
        if p.port:
            port = p.port
        else:
            port = 443 if scheme == "https" else 80
            
        headers = {
            "User-Agent": "okhttp/3.8.0",
            "Cache-Control": "no-cache",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
        }
        if host:
            host_hdr = f"{host}:{port}" if port else f"{host}"
            headers["Host"] = host_hdr
            
        base_url = f"{scheme}://{host}:{port}"
        return base_url, host, port, headers
    
    @staticmethod
    def extract_hostname(url: str) -> str:
        try:
            base_url, host, _, _ = URLProcessor.normalize_and_parse(url)
            return host
        except Exception:
            return ""
    
    @staticmethod
    def get_base_url_only(url: str) -> str:
        base_url, _, _, _ = URLProcessor.normalize_and_parse(url)
        return base_url

# =============================================================================
# GERÇEK M3U BİLGİSİ ÇEKME FONKSİYONU - TAM VE EKSİKSİZ
# =============================================================================

# orumcek_module.py dosyasındaki fetch_real_m3u_info fonksiyonunu bu yeni kodla değiştirin

def fetch_real_m3u_info(base_url, username, password, timeout=10):
    """GERÇEK M3U BİLGİLERİNİ DOĞRU ŞEKİLDE ÇEK - DÜZELTİLMİŞ"""
    try:
        import socket
        import ssl
        from datetime import datetime
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'okhttp/3.8.0',
            'Cache-Control': 'no-cache',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
        })
        session.verify = False
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        
        # 1. ÖNCE TEMEL BİLGİLERİ AL
        player_api_url = f"{base_url}/player_api.php?username={username}&password={password}"
        response = session.get(player_api_url, timeout=timeout)
        
        if response.status_code != 200:
            return None
            
        data = response.json()
        
        # Kullanıcı bilgilerini kontrol et
        user_info = data.get('user_info', {})
        if not user_info:
            return None
            
        # Status kontrolü
        status = user_info.get('status', '')
        if status != 'Active':
            return None
        
        # 2. CANLI KANAL SAYISINI AL - DÜZELTİLMİŞ
        live_channels_count = 0
        try:
            live_url = f"{base_url}/player_api.php?username={username}&password={password}&action=get_live_streams"
            live_response = session.get(live_url, timeout=timeout)
            if live_response.status_code == 200:
                live_data = live_response.json()
                if isinstance(live_data, list):
                    live_channels_count = len(live_data)
                elif isinstance(live_data, dict) and 'streams' in live_data:
                    live_channels_count = len(live_data['streams'])
        except:
            live_channels_count = 0
        
        # 3. VOD SAYISINI AL - DÜZELTİLMİŞ
        vod_count = 0
        try:
            vod_url = f"{base_url}/player_api.php?username={username}&password={password}&action=get_vod_streams"
            vod_response = session.get(vod_url, timeout=timeout)
            if vod_response.status_code == 200:
                vod_data = vod_response.json()
                if isinstance(vod_data, list):
                    vod_count = len(vod_data)
                elif isinstance(vod_data, dict) and 'streams' in vod_data:
                    vod_count = len(vod_data['streams'])
        except:
            vod_count = 0
        
        # 4. SERIES SAYISINI AL - DÜZELTİLMİŞ
        series_count = 0
        try:
            series_url = f"{base_url}/player_api.php?username={username}&password={password}&action=get_series"
            series_response = session.get(series_url, timeout=timeout)
            if series_response.status_code == 200:
                series_data = series_response.json()
                if isinstance(series_data, list):
                    series_count = len(series_data)
                elif isinstance(series_data, dict) and 'series' in series_data:
                    series_count = len(series_data['series'])
        except:
            series_count = 0
        
        # 5. KATEGORİLERİ AL - DÜZELTİLMİŞ
        categories = []
        try:
            # Canlı kategoriler
            live_cat_url = f"{base_url}/player_api.php?username={username}&password={password}&action=get_live_categories"
            live_cat_response = session.get(live_cat_url, timeout=timeout)
            if live_cat_response.status_code == 200:
                live_cat_data = live_cat_response.json()
                if isinstance(live_cat_data, list):
                    for cat in live_cat_data:
                        if isinstance(cat, dict):
                            cat_name = cat.get('category_name', '')
                            if cat_name and cat_name not in categories:
                                categories.append(cat_name)
            
            # VOD kategoriler
            vod_cat_url = f"{base_url}/player_api.php?username={username}&password={password}&action=get_vod_categories"
            vod_cat_response = session.get(vod_cat_url, timeout=timeout)
            if vod_cat_response.status_code == 200:
                vod_cat_data = vod_cat_response.json()
                if isinstance(vod_cat_data, list):
                    for cat in vod_cat_data:
                        if isinstance(cat, dict):
                            cat_name = cat.get('category_name', '')
                            if cat_name and cat_name not in categories:
                                categories.append(cat_name)
                                
            # Series kategoriler
            series_cat_url = f"{base_url}/player_api.php?username={username}&password={password}&action=get_series_categories"
            series_cat_response = session.get(series_cat_url, timeout=timeout)
            if series_cat_response.status_code == 200:
                series_cat_data = series_cat_response.json()
                if isinstance(series_cat_data, list):
                    for cat in series_cat_data:
                        if isinstance(cat, dict):
                            cat_name = cat.get('category_name', '')
                            if cat_name and cat_name not in categories:
                                categories.append(cat_name)
        except:
            categories = []
        
        # 6. DİĞER BİLGİLER - DÜZELTİLMİŞ
        active_cons = user_info.get('active_cons', '0')
        max_connections = user_info.get('max_connections', '1')
        
        # Expiry date
        exp_date = user_info.get('exp_date', '')
        days_left = None
        if exp_date and exp_date != '0' and exp_date != '0000000000':
            try:
                if len(str(exp_date)) == 10:
                    exp_timestamp = int(exp_date)
                    days_left = (datetime.fromtimestamp(exp_timestamp) - datetime.now()).days
                    exp_date = datetime.fromtimestamp(exp_timestamp).strftime('%d-%m-%Y')
            except:
                exp_date = "Bilinmiyor"
        else:
            exp_date = "Bilinmiyor"
        
        # Created at
        created_at = user_info.get('created_at', '')
        if created_at and created_at != '0' and created_at != '0000000000':
            try:
                if len(str(created_at)) == 10:
                    created_at_timestamp = int(created_at)
                    dt = datetime.fromtimestamp(created_at_timestamp)
                    months = {
                        1: "Ocak", 2: "Şubat", 3: "Mart", 4: "Nisan",
                        5: "Mayıs", 6: "Haziran", 7: "Temmuz", 8: "Ağustos", 
                        9: "Eylül", 10: "Ekim", 11: "Kasım", 12: "Aralık"
                    }
                    created_at = f"{dt.day} {months.get(dt.month, '')} {dt.year}"
            except:
                created_at = "Bilinmiyor"
        else:
            created_at = "Bilinmiyor"
        
        # IP bilgisi
        try:
            hostname = urlparse(base_url).hostname
            ip_address = socket.gethostbyname(hostname)
            
            # IP lokasyon
            try:
                ip_response = session.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
                if ip_response.status_code == 200:
                    ip_data = ip_response.json()
                    country_code = ip_data.get('countryCode', 'TR')
                    country_name = ip_data.get('country', 'Türkiye')
                    isp_info = ip_data.get('isp', 'Bilinmiyor')
                else:
                    country_code = "TR"
                    country_name = "Türkiye"
                    isp_info = "Bilinmiyor"
            except:
                country_code = "TR"
                country_name = "Türkiye"
                isp_info = "Bilinmiyor"
        except:
            ip_address = "Bilinmiyor"
            country_code = "TR"
            country_name = "Türkiye"
            isp_info = "Bilinmiyor"
        
        # Feed sayısı - DÜZELTİLMİŞ
        feed_count = 0
        try:
            if live_channels_count > 0:
                # Canlı stream verilerini al
                live_url = f"{base_url}/player_api.php?username={username}&password={password}&action=get_live_streams"
                live_response = session.get(live_url, timeout=timeout)
                if live_response.status_code == 200:
                    live_data = live_response.json()
                    streams = []
                    
                    if isinstance(live_data, list):
                        streams = live_data
                    elif isinstance(live_data, dict) and 'streams' in live_data:
                        streams = live_data['streams']
                    
                    for stream in streams:
                        if isinstance(stream, dict):
                            name = stream.get('name', '').lower()
                            if 'feed' in name or 'radio' in name:
                                feed_count += 1
        except:
            feed_count = 0
        
        feed_ratio = round((feed_count / live_channels_count) if live_channels_count > 0 else 0.0, 4)
        
        # Güvenilirlik skoru - DÜZELTİLMİŞ
        def calculate_reliability_score(ch_count, cat_count, days):
            try:
                score = 0.0
                
                if ch_count > 1000:
                    score += 40
                elif ch_count > 500:
                    score += 30
                elif ch_count > 200:
                    score += 20
                elif ch_count > 50:
                    score += 10
                    
                if cat_count > 20:
                    score += 30
                elif cat_count > 10:
                    score += 20
                elif cat_count > 5:
                    score += 10
                    
                if days and days > 180:
                    score += 30
                elif days and days > 90:
                    score += 20
                elif days and days > 30:
                    score += 10
                    
                final_score = min(5.0, score / 20.0)
                return round(final_score, 2)
                
            except Exception:
                return 3.0
        
        reliability_score = calculate_reliability_score(live_channels_count, len(categories), days_left)
        
        # SONUÇ - DÜZELTİLMİŞ
        result = {
            # Temel bilgiler
            'user_info': user_info,
            
            # Kategori ve içerik bilgileri - DÜZELTİLMİŞ
            'categories': categories,
            'total_available_channels': live_channels_count,
            'available_movies': vod_count,
            'available_series': series_count,
            
            # IP ve lokasyon
            'ip_address': ip_address,
            'country_code': country_code,
            'country_name': country_name,
            'isp': isp_info,
            'hostname': hostname,
            'days_left': days_left,
            
            # MESAJ FORMATLAYICI İÇİN GEREKLİ TÜM ALANLAR - DÜZELTİLMİŞ
            'status': '✅ Active',
            'status_raw': 'Active',
            'kanalsayisi': str(live_channels_count),
            'kanalsayisi_int': live_channels_count,
            'filmsayisi': str(vod_count),
            'dizisayisi': str(series_count),
            'exp_date': exp_date,
            'created_at': created_at,
            'active_cons': active_cons,
            'max_connections': max_connections,
            'ip': ip_address,
            'country_name': country_name,
            'country_code': country_code,
            'isp': isp_info,
            'kategori_listesi': categories,
            'gorunen_kategoriler': categories[:8],
            'realm': base_url,
            'port': '',
            'message': user_info.get('message', ''),
            'form': user_info.get('allowed_output_formats', ['m3u8', 'ts']),
            'days_left': days_left,
            
            # AI yorum için gerekli alanlar - DÜZELTİLMİŞ
            'feed_count_int': feed_count,
            'feed_ratio': feed_ratio,
            'reliability_score': reliability_score,
            'detected_similar_count': 0,
        }
        
        print(f"✅ BAŞARILI: {live_channels_count} kanal, {len(categories)} kategori, {vod_count} film, {series_count} dizi")
        return result
        
    except Exception as e:
        print(f"❌ Gerçek M3U bilgi çekme hatası: {e}")
        import traceback
        traceback.print_exc()
        return None

# =============================================================================
# YASAKLI KELİME ve KATEGORİ FONKSİYONLARI
# =============================================================================

def yasakli_kelimeleri_yukle(path=None):
    try:
        if GITHUB_REPO and GITHUB_TOKEN:
            gh_load_all()
            cache = get_github_cache()
            return cache["kelimeler"]["lines"] or []
            
        out = []
        p = path or YASAKLI_KELIMELER_FILE
        try:
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                out = [ln.strip().lower() for ln in f if ln.strip()]
        except FileNotFoundError:
            out = []
        return out
    except Exception:
        return []

def yasakli_kategorileri_yukle(path=None):
    try:
        if GITHUB_REPO and GITHUB_TOKEN:
            gh_load_all()
            cache = get_github_cache()
            return cache["kategoriler"]["lines"] or []
            
        p = path or YASAKLI_KATEGORI_FILE
        out = []
        try:
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    normalized = re.sub(r'[^\w\s|.-]', '', line.replace('--','|').replace('_',' ')).strip().lower()
                    if normalized and normalized not in out:
                        out.append(normalized)
        except FileNotFoundError:
            out = []
        return out
    except Exception as e:
        print(f"yasakli_kategorileri_yukle hata: {e}")
        return []

def yasakli_oge_ekle(deger: str, tur: str, path=None):
    try:
        yeni = (deger or "").strip()
        if not yeni:
            return
            
        if tur == "kelime":
            host_only = extract_hostname(yeni) or re.sub(r'[^a-zA-Z0-9.-]', '', yeni).strip()
            normalized_value = host_only.lower()
        elif tur == "kategori":
            normalized_value = re.sub(r'[^\w\s|.-]', '', yeni.replace('--','|').replace('_',' ')).strip().lower()
        else:
            return
            
        if not normalized_value:
            return

        if GITHUB_REPO and GITHUB_TOKEN:
            try:
                gh_lock = get_github_lock()
                cache = get_github_cache()
                with gh_lock:
                    if tur == "kelime":
                        cache["kelimeler"]["lines"].append(normalized_value)
                    else:
                        cache["kategoriler"]["lines"].append(yeni)
            except Exception:
                pass
        else:
            if tur == "kelime":
                p = path or YASAKLI_KELIMELER_FILE
            else:
                p = path or YASAKLI_KATEGORI_FILE
                
            with _FILE_LOCK:
                with open(p, 'a', encoding='utf-8', errors='ignore') as f:
                    f.write("\n" + (yeni if tur == "kategori" else normalized_value))
                    
    except Exception as e:
        print(f"yasakli_oge_ekle hata: {e}")

def yasakli_kategori_var_mi(kategoriler, yasakli_kategoriler=None, host=""):
    try:
        if not kategoriler:
            return False
    except Exception:
        return False

    if yasakli_kategoriler is None:
        yasakli_kategoriler = yasakli_kategorileri_yukle()

    normalized_yasakli = []
    for y in (yasakli_kategoriler or []):
        try:
            if not y:
                continue
            temiz = re.sub(r'[^\w\s]', '', str(y)).strip().lower()
            if temiz:
                normalized_yasakli.append(temiz)
        except Exception:
            continue

    for kategori in (kategoriler or []):
        try:
            if not kategori:
                continue
            temiz_kat = re.sub(r'[^\w\s]', '', str(kategori)).strip().lower()
            if not temiz_kat:
                continue
                
            for temiz_y in normalized_yasakli:
                if temiz_kat == temiz_y:
                    print(f"🚫 YASAKLI KATEGORİ BULUNDU: {kategori}")
                    try:
                        lower_host = extract_hostname(host or "")
                        if lower_host:
                            yasakli_oge_ekle(lower_host, "kelime")
                    except Exception as e:
                        print(f"❌ DNS ekleme hatası: {e}")

                    try:
                        yasakli_oge_ekle(kategori, "kategori")
                    except Exception as e:
                        print(f"❌ Kategori ekleme hatası: {e}")
                    
                    return True
        except Exception as e:
            print(f"❌ Kategori işleme hatası: {e}")
            continue
    return False

# =============================================================================
# DNS GRUP İŞLEMLERİ
# =============================================================================

def load_tespit_edilen_gruplar(path=TESPIT_JSON):
    try:
        if not os.path.exists(path):
            return {}
            
        return load_json_safe(path)
    except Exception as e:
        print(f"load_tespit_edilen_gruplar hata: {e}")
        return {}

def save_tespit_edilen_gruplar(groups, path=TESPIT_JSON):
    try:
        save_json_safe(path, groups)
        return True
    except Exception as e:
        print(f"save_tespit_edilen_gruplar hata: {e}")
        return False

def normalize_base(u: str) -> str:
    try:
        if not u:
            return ""
        if not u.startswith("http"):
            u = "http://" + u
        p = urlparse(u)
        net = p.netloc or p.path
        scheme = p.scheme or "http"
        return f"{scheme}://{net}"
    except Exception:
        return u

def benzer_dns_islemleri(islem_tipi, **kwargs):
    try:
        islem_tipi = islem_tipi.lower()
        
        if islem_tipi == 'bul':
            # ✅ SADECE liste dön (TEK değer)
            return _benzer_linkleri_bul_internal(
                kwargs.get('kategoriler', []), 
                kwargs.get('mevcut_alan', '')
            )
            
        elif islem_tipi == 'degistir':
            # ✅ İKİ değer dön: (sayı, liste)
            return _replace_with_group_leader_internal(
                kwargs.get('source_path', '')
            )
            
        elif islem_tipi == 'getir':
            # ✅ İKİ değer dön: (liste, sayı)
            detected_dns_list = getattr(self.state, 'dns_list', [])  # STATE'ten al
            detected_count = getattr(self.state, 'tespit_edilen_benzer_sayisi', 0)
            return detected_dns_list, detected_count
            
        else:
            # ✅ Varsayılan: TEK değer dön
            return []
            
    except Exception as e:
        print(f"❌ Benzer DNS işlemleri hatası: {e}")
        return []  # ⬅️ HATA DURUMUNDA TEK DEĞER

def _replace_with_group_leader_internal(source_path: str) -> Tuple[int, List[str]]:
    try:
        if not source_path or not os.path.exists(source_path):
            return 0, []

        with open(source_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [ln.rstrip("\n") for ln in f if ln.strip()]

        raw_groups = load_tespit_edilen_gruplar() or {}
        
        host_to_leader = {}
        for g, val in raw_groups.items():
            if isinstance(val, dict):
                dns_listesi = val.get("dns_listesi", [])
                if dns_listesi:
                    leader_norm = normalize_base(dns_listesi[0])
                    for u in dns_listesi:
                        nu = normalize_base(u)
                        if not nu:
                            continue
                        try:
                            p = urlparse(nu)
                            net = p.netloc or p.path
                            if net:
                                host_to_leader[net] = leader_norm
                        except Exception:
                            continue

        replaced_count = 0
        replaced_dns = set()
        new_lines = []
        
        for ln in lines:
            try:
                stripped = ln.strip()
                p = urlparse(stripped if stripped.startswith("http") else "http://" + stripped)
                net = p.netloc or p.path
                if not net:
                    new_lines.append(ln)
                    continue
                    
                leader_norm = host_to_leader.get(net)
                if leader_norm:
                    leader_net = urlparse(leader_norm).netloc or urlparse(leader_norm).path
                    if leader_net and leader_net != net:
                        new_ln = ln.replace(net, leader_net)
                        if new_ln != ln:
                            replaced_count += 1
                            replaced_dns.add(net)
                            new_lines.append(new_ln)
                            continue
            except Exception:
                pass
            new_lines.append(ln)

        if replaced_count > 0:
            atomic_write(source_path, "\n".join(new_lines))

        return replaced_count, sorted(replaced_dns)
        
    except Exception as e:
        print(f"❌ Grup lideri değiştirme hatası: {e}")
        return 0, []

def _benzer_linkleri_bul_internal(kategoriler: List[str], mevcut_alan: str) -> List[str]:
    try:
        if not kategoriler:
            return []
            
        temiz_kategoriler = [kat.strip() for kat in kategoriler[:6] if kat and kat.strip()]
        
        if not temiz_kategoriler:
            return []

        mevcut_norm = normalize_base(mevcut_alan)
        mevcut_kat_set = set(temiz_kategoriler)
        
        yeni_kategori_str = "||".join(temiz_kategoriler)
        
        raw_groups = load_tespit_edilen_gruplar()
        benzer_dnsler = set()
        hedef_grup_adi = None

        for g_name, grp_content in raw_groups.items():
            if not isinstance(grp_content, dict):
                continue
                
            dns_listesi = grp_content.get("dns_listesi", [])
            
            for dns in dns_listesi:
                if normalize_base(dns) == mevcut_norm:
                    hedef_grup_adi = g_name
                    
                    for diger_dns in dns_listesi:
                        diger_norm = normalize_base(diger_dns)
                        if diger_norm and diger_norm != mevcut_norm:
                            benzer_dnsler.add(diger_dns)
                    break
            
            if hedef_grup_adi:
                break

        if not hedef_grup_adi:
            for g_name, grp_content in raw_groups.items():
                if not isinstance(grp_content, dict):
                    continue
                    
                for key, value in grp_content.items():
                    if key.startswith("Kategori") and isinstance(value, str):
                        if '||' in value:
                            grup_kat_parcalar = [k.strip() for k in value.split('||') if k.strip()]
                            grup_kat_set = set(grup_kat_parcalar)
                        else:
                            grup_kat_set = {value.strip()} if value.strip() else set()
                        
                        if mevcut_kat_set == grup_kat_set:
                            hedef_grup_adi = g_name
                            
                            dns_listesi = grp_content.get("dns_listesi", [])
                            for dns in dns_listesi:
                                dns_norm = normalize_base(dns)
                                if dns_norm and dns_norm != mevcut_norm:
                                    benzer_dnsler.add(dns)
                            break
                
                if hedef_grup_adi:
                    break

        if hedef_grup_adi:
            hedef_grup = raw_groups[hedef_grup_adi]
            
            kategori_mevcut = False
            for key, value in hedef_grup.items():
                if key.startswith("Kategori") and isinstance(value, str):
                    if '||' in value:
                        grup_kat_set = set([k.strip() for k in value.split('||') if k.strip()])
                    else:
                        grup_kat_set = {value.strip()} if value.strip() else set()
                    
                    if mevcut_kat_set == grup_kat_set:
                        kategori_mevcut = True
                        break
            
            if not kategori_mevcut:
                kategori_sayisi = sum(1 for key in hedef_grup.keys() if key.startswith("Kategori"))
                yeni_kategori_anahtar = f"Kategori{kategori_sayisi + 1}"
                hedef_grup[yeni_kategori_anahtar] = yeni_kategori_str
            
            save_tespit_edilen_gruplar(raw_groups)
            return list(benzer_dnsler)

        idx = 1
        while f'Gurup{idx}' in raw_groups:
            idx += 1
        
        new_group_name = f'Gurup{idx}'
        new_group_data = {
            "Kategori1": yeni_kategori_str,
            "dns_listesi": [mevcut_alan]
        }
        
        raw_groups[new_group_name] = new_group_data
        save_tespit_edilen_gruplar(raw_groups)
        
        return []
            
    except Exception as e:
        print(f"❌ Benzer link bulma hatası: {e}")
        return []

# =============================================================================
# DOSYA İŞLEME FONKSİYONLARI
# =============================================================================

def preprocess_source_file(path, yasakli_kelimeler):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [ln.rstrip("\n") for ln in f]
    except Exception:
        return 0, 0, 0
    total_before = len(lines)
    removed_banned = 0
    kept = []
    for ln in lines:
        if not ln.strip():
            continue
        lower = ln.lower()
        banned = False
        for kw in yasakli_kelimeler:
            if kw and kw in lower:
                banned = True
                removed_banned += 1
                break
        if not banned:
            kept.append(ln)
    seen = set()
    unique = []
    removed_duplicates = 0
    for ln in kept:
        if ln in seen:
            removed_duplicates += 1
            continue
        seen.add(ln)
        unique.append(ln)
    try:
        atomic_write(path, "\n".join(unique))
    except Exception:
        pass
    new_total = len(unique)
    return new_total, removed_duplicates, removed_banned

def load_aday_dns(path=ADAY_DNS_FILE):
    out = []
    try:
        print(f"🔍 Aday DNS yükleniyor: {path}")
        
        # GitHub cache kontrolü
        if GITHUB_REPO and GITHUB_TOKEN:
            try:
                cache = get_github_cache()
                print(f"📦 GitHub cache: {cache}")
                if cache and "adaydns" in cache:
                    out = list(cache["adaydns"].get("lines", []) or [])
                    print(f"✅ GitHub'dan {len(out)} DNS yüklendi")
                    if out:
                        return out
            except Exception as e:
                print(f"❌ GitHub cache hatası: {e}")
        
        # Local dosya kontrolü
        print(f"📁 Local dosya kontrolü: {os.path.exists(path)}")
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for ln in f:
                    ln = ln.strip()
                    if ln:
                        out.append(ln)
            print(f"✅ Local'den {len(out)} DNS yüklendi")
        else:
            print(f"❌ Dosya bulunamadı: {path}")
            
    except Exception as e:
        print(f"❌ DNS listesi yükleme hatası: {e}")
    
    print(f"📊 Toplam yüklenen DNS: {len(out)}")
    return out

# =============================================================================
# TELEGRAM MESAJ GÖNDERİM SİSTEMİ - TAM VE EKSİKSİZ
# =============================================================================

class TelegramSender:
    def __init__(self, bot_token, chat_ids):
        self.bot_token = bot_token
        self.chat_ids = chat_ids
        self.http_client = httpx.Client(timeout=10.0)
        self.specific_group_id = -1002042461006  # ÇOKLU GRUP
        self.scraper_group_id = -1001844205745   # SCRAPER GRUP
        self.normal_group_id = -1001948263686    # NORMAL GRUP
        self.parent_widget = None

    def set_parent_widget(self, parent_widget):
        """Parent widget'ı ayarla"""
        self.parent_widget = parent_widget

    def reset_group_status(self):
        """Tüm grup durumlarını sarı (bekle) durumuna resetle"""
        try:
            if self.parent_widget and hasattr(self.parent_widget, 'state'):
                for chat_id in self.chat_ids:
                    self.parent_widget.state.message_status[chat_id] = {
                        'state': 'bekle',
                        'ts': None
                    }
                print("🔄 Grup durumları resetlendi (sarı)")
        except Exception as e:
            print(f"❌ Grup resetleme hatası: {e}")
    
    def update_group_status(self, chat_id, status, timestamp=None):
        """Grup durumunu güncelle"""
        try:
            if self.parent_widget and hasattr(self.parent_widget, 'state'):
                self.parent_widget.state.message_status[chat_id] = {
                    'state': status,
                    'ts': timestamp or datetime.now().strftime('%H:%M:%S')
                }
                print(f"✅ Grup durumu güncellendi: {chat_id} -> {status}")
        except Exception as e:
            print(f"❌ Grup durumu güncelleme hatası: {e}")   
            
    def send_to_groups(self, message_data, max_connections=1):
        """GRUP DAĞILIMI - ORJİNAL KODA TAM UYGUN"""
        results = {}
        
        # ÖNCE TÜM GRUPLARI SARI YAP
        self.reset_group_status()
        
        for chat_id in self.chat_ids:
            try:
                # ÖNCE "GÖNDERİLİYOR" DURUMUNA GETİR (TURUNCU)
                self.update_group_status(chat_id, 'gonderiliyor')

                # ✅ ORJİNAL KOD MANTIĞI:
                if max_connections > 1:
                    # ÇOKLU BAĞLANTI - SADECE ÇOKLU GRUBA GÖNDER
                    if chat_id == self.specific_group_id:
                        result = self._send_message(chat_id, message_data)
                        if result.get('ok'):
                            self.update_group_status(chat_id, 'gonderildi')
                            print(f"✅ Çoklu bağlantı mesajı {chat_id} grubuna gönderildi")
                        else:
                            self.update_group_status(chat_id, 'hata')
                        results[chat_id] = result
                    else:
                        # Diğer gruplara HİÇ GÖNDERME
                        results[chat_id] = {'ok': True, 'skipped': 'Çoklu bağlantı - sadece çoklu gruba'}
                        print(f"⏭️ {chat_id} atlandı (çoklu bağlantı modu)")
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
                        print(f"✅ Mesaj {chat_id} grubuna gönderildi")
                    else:
                        self.update_group_status(chat_id, 'hata')
                        print(f"❌ Mesaj {chat_id} grubuna gönderilemedi: {result.get('error')}")
                    
                    results[chat_id] = result
                
                time.sleep(1)  # ✅ Telegram rate limit için 1 saniye bekle
                
            except Exception as e:
                error_msg = f"Gönderim hatası: {str(e)}"
                results[chat_id] = {'ok': False, 'error': error_msg}
                self.update_group_status(chat_id, 'hata')
                print(f"❌ {chat_id} grubuna gönderim hatası: {e}")

        # SONUÇ ÖZETİ
        success_count = sum(1 for r in results.values() if r.get('ok') and 'skipped' not in str(r))
        print(f"📊 Gönderim özeti: {success_count}/{len(results)} grup başarılı | Max Connections: {max_connections}")
        
        return results


    def _send_message(self, chat_id, message_data):
        """Mesaj gönder - DÜZELTİLMİŞ"""
        try:
            # Eğer message_data string ise dict'e çevir
            if isinstance(message_data, str):
                message_data = {'text': message_data, 'parse_mode': 'HTML'}
            
            payload = {
                'chat_id': chat_id,
                'text': message_data.get('text', ''),
                'parse_mode': message_data.get('parse_mode', 'HTML')
            }
            
            if message_data.get('keyboard'):
                payload['reply_markup'] = json.dumps({
                    'inline_keyboard': message_data['keyboard']
                }, ensure_ascii=False)
            
            return self._send_telegram_message("sendMessage", payload)
        except Exception as e:
            return {'ok': False, 'error': str(e)}
    
    def _create_short_message(self, message_data):
        """Scraper grup için kısa mesaj"""
        try:
            text = message_data['text']
            import re
            clean_text = re.sub(r'<[^>]+>', '', text)
            
            lines = clean_text.split('\n')
            short_lines = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                if any(keyword in line for keyword in [
                    'M3u bilgileri', '🌍', '👤', '🔑', 
                    '💫 @Türkei', 'Tespit edilen DNS'
                ]):
                    short_lines.append(line)
                
                if 'http' in line and ('get.php' in line or 'type=m3u' in line):
                    short_lines.append(line)
                    break
            
            short_text = '\n'.join(short_lines)
            
            return {
                'text': short_text,
                'keyboard': message_data.get('keyboard', []),
                'parse_mode': 'HTML'  # ✅ None yerine HTML
            }
            
        except Exception as e:
            print(f"❌ Kısa mesaj oluşturma hatası: {e}")
            return message_data
    
    def send_error_message(self, chat_id, message_text, url_data=None):
        """HATA MESAJI - DÜZELTİLMİŞ"""
        try:
            # ÖNCE "GÖNDERİLİYOR" DURUMU
            self.update_group_status(chat_id, 'gonderiliyor')

            # Hata mesajı butonları
            keyboard = []
            if url_data:
                try:
                    from orumcek_butonmodulu import buton_yoneticisi
                    keyboard = buton_yoneticisi.hata_butonlari_olustur(url_data)
                except ImportError:
                    print("❌ buton_yoneticisi bulunamadı")
            
            payload = {
                'chat_id': chat_id,
                'text': message_text,
                'parse_mode': 'HTML'
            }
            
            if keyboard:
                payload['reply_markup'] = json.dumps({
                    'inline_keyboard': keyboard
                }, ensure_ascii=False)
            
            result = self._send_telegram_message("sendMessage", payload)
            
            # ✅ DURUM GÜNCELLEME
            if result.get('ok'):
                self.update_group_status(chat_id, 'gonderildi')
                print(f"✅ Hata mesajı {chat_id} grubuna gönderildi")
            else:
                self.update_group_status(chat_id, 'hata')
                print(f"❌ Hata mesajı gönderilemedi: {result.get('error')}")
            
            return result
            
        except Exception as e:
            print(f"❌ Hata mesajı gönderme hatası: {e}")
            self.update_group_status(chat_id, 'hata')
            return {'ok': False, 'error': str(e)}
    
    def _send_telegram_message(self, method, payload):
        """Telegram API çağrısı - DÜZELTİLMİŞ"""
        url = f"https://api.telegram.org/bot{self.bot_token}/{method}"
        
        try:
            response = self.http_client.post(url, json=payload)
            result = response.json()
            
            if result.get('ok'):
                print(f"✅ Telegram API başarılı: {method}")
                return {'ok': True, 'result': result.get('result')}
            else:
                error_msg = result.get('description', 'Unknown error')
                print(f"❌ Telegram API hatası: {error_msg}")
                
                # HTML parse hatası - butonları kaldır ve tekrar dene
                if 'can\'t parse entities' in error_msg:
                    print("🔄 HTML parse hatası, butonlar kaldırılıyor...")
                    payload.pop('reply_markup', None)
                    payload['parse_mode'] = None  # HTML parsing'i kapat
                    return self._send_telegram_message(method, payload)
                    
                return {'ok': False, 'error': error_msg}
                
        except Exception as e:
            error_msg = f"Telegram bağlantı hatası: {str(e)}"
            print(f"❌ {error_msg}")
            return {'ok': False, 'error': error_msg}
    
    def send_broadcast_message(self, message_data, message_type="success", url_data=None, max_connections=1):
        results = {}
        
        self.reset_group_status()
        
        keyboard = []
        if url_data:
            try:
                from orumcek_butonmodulu import buton_yoneticisi
                
                if message_type in ["success", "account_disabled", "expired_account"]:
                    keyboard = buton_yoneticisi.basari_butonlari_olustur(url_data, max_connections)
                else:
                    keyboard = buton_yoneticisi.hata_butonlari_olustur(url_data)
                    
            except Exception:
                keyboard = []
        
        if keyboard:
            message_data['keyboard'] = keyboard
        
        is_multi_connection = max_connections > 1
        
        for chat_id in self.chat_ids:
            try:
                if self.parent_widget and hasattr(self.parent_widget, 'state'):
                    self.parent_widget.state.message_status[chat_id] = {
                        'state': 'gonderiliyor', 
                        'ts': None
                    }

                if message_type == "success":
                    if is_multi_connection:
                        if chat_id == self.specific_group_id:
                            result = self._send_message(chat_id, message_data)
                        else:
                            result = {'ok': True, 'skipped': 'Çoklu bağlantı - diğer gruplara gönderilmez'}
                    else:
                        if chat_id == self.normal_group_id:
                            result = self._send_message(chat_id, message_data)
                        elif chat_id == self.scraper_group_id:
                            short_message = self._create_short_message(message_data)
                            result = self._send_message(chat_id, short_message)
                        else:
                            result = {'ok': True, 'skipped': 'Normal bağlantı - çoklu gruba gönderilmez'}
                            
                elif message_type in ["error", "account_disabled", "expired_account"]:
                    if message_type in ["account_disabled", "expired_account"]:
                        result = self._send_message(chat_id, message_data)
                    else:
                        if chat_id == self.scraper_group_id:
                            result = self._send_message(chat_id, message_data)
                        else:
                            result = {'ok': True, 'skipped': f'Hata mesajı sadece scraper grubuna - {message_type}'}
                            
                elif message_type == "blocked":
                    result = {'ok': True, 'skipped': 'Yasaklı mesaj gönderilmez'}
                    
                else:
                    result = self._send_message(chat_id, message_data)
                
                if result.get('ok') and 'skipped' not in str(result):
                    if self.parent_widget and hasattr(self.parent_widget, 'state'):
                        self.parent_widget.state.message_status[chat_id] = {
                            'state': 'gonderildi',
                            'ts': datetime.now().strftime('%H:%M:%S')
                        }
                elif not result.get('ok'):
                    if self.parent_widget and hasattr(self.parent_widget, 'state'):
                        self.parent_widget.state.message_status[chat_id] = {
                            'state': 'hata',
                            'ts': datetime.now().strftime('%H:%M:%S')
                        }
                
                results[chat_id] = result
                time.sleep(1)
                
            except Exception:
                results[chat_id] = {'ok': False, 'error': 'Gönderim hatası'}
                if self.parent_widget and hasattr(self.parent_widget, 'state'):
                    self.parent_widget.state.message_status[chat_id] = {
                        'state': 'hata',
                        'ts': datetime.now().strftime('%H:%M:%S')
                    }
        
        return results

# =============================================================================
# M3U İŞLEME SİSTEMİ - GERÇEK FETCH İLE
# =============================================================================

# orumcek_module.py - TAM M3UProcessor SINIFI
class M3UProcessor:
    def __init__(self, state, bot_token, chat_ids, parent_widget=None):
        self.state = state
        self.parent_widget = parent_widget
        self.telegram_sender = TelegramSender(bot_token, chat_ids)
        # ✅ DÜZELTME: set_parent_widget metodunu kullan
        if parent_widget:
            self.telegram_sender.set_parent_widget(parent_widget)
        
    def process_url(self, url):
        """URL işle - DETAYLI HATA YÖNETİMİ İLE"""
        try:
            base_candidate = URLProcessor.get_base_url_only(url or "")
            host = URLProcessor.extract_hostname(url or "")
            
            if not host:
                self._set_error_info(url, 'Geçersiz URL/host yok', 'Invalid input')
                return {'status': 'error', 'error': 'Geçersiz URL', 'error_detail': 'Host bulunamadı'}
            
            # Yasaklı kelime kontrolü
            yasakli_kelimeler = self.state.yasakli_kelimeler or yasakli_kelimeleri_yukle()
            if any(kw for kw in yasakli_kelimeler if kw and kw in host.lower()):
                self.state.engellenen_msg += 1
                self.state.yasakli_dns_count = len(yasakli_kelimeler)
                self._set_error_info(host, 'Host yasaklı kelime içeriyor', 'Engellendi')
                return {'status': 'blocked', 'reason': 'Yasaklı DNS'}
            
            # URL'den kullanıcı bilgilerini çıkar
            parsed_input = urlparse(url)
            qs = parse_qs(parsed_input.query)
            user = qs.get('username', [None])[0] or ""
            pas = qs.get('password', [None])[0] or ""
            
            if not user or not pas:
                self._set_error_info(base_candidate, 'Eksik username/password', 'Invalid credentials')
                return {'status': 'error', 'error': 'Eksik kullanıcı bilgisi'}
            
            original_base = URLProcessor.get_base_url_only(base_candidate)
            
            # GERÇEK M3U BİLGİSİNİ ÇEK
            info = fetch_real_m3u_info(original_base, user, pas)
            
            if info:
                return self.handle_successful_url(original_base, info, user, pas, url)
            else:
                # DETAYLI HATA TESPİTİ
                error_detail = self._detect_detailed_error(original_base, user, pas)
                return self.handle_failed_url(original_base, user, pas, url, "connection_error", error_detail)
                
        except Exception as e:
            self._set_error_info(url, f'İşlem hatası: {str(e)}', 'Error')
            return {'status': 'error', 'error': str(e), 'error_detail': f'İşlem hatası: {str(e)}'}

    def _detect_detailed_error(self, base_url, username, password):
        """ORJİNAL KODDAKİ TÜM HATA TÜRLERİNİ TESPİT ET - GÜNCELLENMİŞ"""
        try:
            import socket
            import ssl
            import requests
            
            # 1. DNS ÇÖZÜMLEME TESTİ
            hostname = urlparse(base_url).hostname
            try:
                socket.gethostbyname(hostname)
            except socket.gaierror:
                return "DNS çözümleme hatası - sunucu bulunamadı"
            
            # 2. PORT ERİŞİM TESTİ
            parsed = urlparse(base_url)
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((hostname, port))
                sock.close()
                
                if result != 0:
                    return "Bağlantı hatası - sunucu kapalı veya port erişilemez"
            except:
                return "Socket bağlantı hatası"
            
            # 3. SSL TESTİ (HTTPS için)
            if parsed.scheme == 'https':
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            pass
                except ssl.SSLError as e:
                    return f"SSL/TLS hatası - {str(e)}"
                except Exception as e:
                    return f"HTTPS bağlantı hatası - {str(e)}"
            
            # 4. HTTP İSTEKLERİ İLE DETAYLI KONTROL - ORJİNAL KOD MANTIĞI
            session = requests.Session()
            session.verify = False
            requests.packages.urllib3.disable_warnings()
            
            test_urls = [
                f"{base_url}/player_api.php?username={username}&password={password}",
                f"{base_url}/panel_api.php?username={username}&password={password}",
                base_url  # Sadece base URL'yi de test et
            ]
            
            for test_url in test_urls:
                try:
                    response = session.get(test_url, timeout=10, allow_redirects=True)
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            
                            # ✅✅✅ ORJİNAL KODDAKİ USER_INFO KONTROLÜ
                            user_info = data.get("user_info") or data.get("userInfo") or data.get("user")
                            
                            if user_info:
                                status_val = user_info.get("status")
                                if status_val:
                                    status_norm = str(status_val).strip().lower()
                                    
                                    # ✅✅✅ HESAP KAPATILMIŞ - ORJİNAL KOD MANTIĞI
                                    if status_norm in ("disabled", "pasif", "kapalı", "kapatılmış", "deactive", "inactive"):
                                        return "ACCOUNT_DISABLED"
                                    
                                    # ✅✅✅ HESAP SÜRESİ DOLMUŞ - ORJİNAL KOD MANTIĞI
                                    if status_norm not in ("active", "aktif"):
                                        if "expired" in status_norm or "süresi dolmuş" in status_norm or "bitmiş" in status_norm:
                                            exp_date = user_info.get("exp_date") or data.get("exp_date")
                                            created_at = user_info.get("created_at")
                                            exp_info = {
                                                'status': status_val,
                                                'exp_date': exp_date,
                                                'created_at': created_at,
                                            }
                                            return f"EXPIRED_ACCOUNT:{json.dumps(exp_info)}"
                                        
                                        # ✅✅✅ BAN VEYA FAKE HESAP - ORJİNAL KOD MANTIĞI
                                        return f"BAN_OR_FAKE:{status_val}"
                                    
                                    # ✅✅✅ STATUS AKTİF AMA CREATED_AT KONTROLÜ
                                    created_at = user_info.get("created_at")
                                    if not created_at or str(created_at).strip() in ("", "0", "null", "none"):
                                        return "Geçersiz hesap - created_at bilgisi yok"
                                    
                                    # ✅✅✅ STATUS AKTİF VE HER ŞEY NORMAL AMA BAŞKA BİR HATA
                                    return "Bağlantı başarılı ama içerik hatası"
                            
                            return "JSON yanıt alındı ama user_info bulunamadı"
                            
                        except json.JSONDecodeError:
                            if "get.php" in test_url:
                                return "M3U linki çalışıyor ama API yanıtı geçersiz"
                            return "JSON parse hatası - geçersiz yanıt formatı"
                    
                    # HTTP STATUS KODLARI
                    elif response.status_code == 401:
                        return "401 Unauthorized - geçersiz kullanıcı/şifre"
                    elif response.status_code == 403:
                        return "403 Forbidden - erişim engellendi"
                    elif response.status_code == 404:
                        return "404 Not Found - endpoint bulunamadı"
                    elif response.status_code == 500:
                        return "500 Internal Server Error - sunucu hatası"
                    elif response.status_code == 502:
                        return "502 Bad Gateway - ağ hatası"
                    elif response.status_code == 503:
                        return "503 Service Unavailable - sunucu bakımda"
                    elif 400 <= response.status_code < 500:
                        return f"HTTP {response.status_code} İstemci Hatası"
                    elif 500 <= response.status_code < 600:
                        return f"HTTP {response.status_code} Sunucu Hatası"
                        
                except requests.exceptions.ConnectTimeout:
                    return "Bağlantı zaman aşımı - sunucu yanıt vermiyor"
                except requests.exceptions.ReadTimeout:
                    return "Okuma zaman aşımı - sunucu yavaş yanıt veriyor"
                except requests.exceptions.ConnectionError:
                    return "Bağlantı hatası - ağ sorunu"
                except requests.exceptions.SSLError:
                    return "SSL sertifika hatası"
                except Exception:
                    continue
            
            return "Tüm endpoint'ler denendi - bağlantı kurulamadı"
            
        except Exception as e:
            return f"Hata analiz hatası: {str(e)}"

    def handle_failed_url(self, original_base, user, pas, original_url, error_type="normal", error_detail=""):
        """ORJİNAL KODA TAM UYUMLU: Başarısız URL işleme - ORJİNAL KODDAKİ broadcast_error_to_chats'e göre"""
        try:
            if not error_detail:
                error_detail = self._detect_detailed_error(original_base, user, pas)
            
            # ✅ BUTONLAR İÇİN URL DATA OLUŞTUR (ORJİNAL KOD MANTIĞI)
            url_data = {
                'base_url': original_base,
                'username': user,
                'password': pas,
                'm3u_link': original_base + f"/get.php?username={user}&password={pas}&type=m3u_plus"
            }
            
            # ACCOUNT_DISABLED ÖZEL İŞLEM - ORJİNAL KOD GİBİ
            if error_detail == "ACCOUNT_DISABLED":
                self.state.gonderilen += 1
                self.state.toplam_hata += 1
                self._set_error_info(original_base, 'Hesap kapatılmış (disabled)', 'ACCOUNT_DISABLED')
                
                disabled_msg = (
                    "⏰ HESAP KAPATILMIŞ ⏰\n\n"
                    f"🌍 {original_base}\n"
                    f"👤 User➢ {user}\n"
                    f"🔑 Pass➢ {(pas[:2] + '****') if pas else '****'}\n\n"
                    "⚠️ Bu hesap tespit edilip kapatılmış\n\n"
                    "💫 @Türkei Xstream İnjecktion Team"
                )
                
                # ✅ ORJİNAL KOD: Hesap kapalı mesajı için 3 buton
                from orumcek_butonmodulu import buton_yoneticisi
                keyboard = buton_yoneticisi.hata_butonlari_olustur(url_data, "account_disabled")
                
                mesaj_paketi = {
                    'text': disabled_msg,
                    'parse_mode': 'HTML',
                    'url_data': url_data,
                    'keyboard': keyboard  # ✅ ORJİNAL KODDAKİ 3 BUTON
                }
                
                return {
                    'status': 'error', 
                    'error': 'ACCOUNT_DISABLED',
                    'error_detail': 'Hesap kapatılmış (disabled)',
                    'mesaj_paketi': mesaj_paketi,
                    'broadcast_all': True,  # ✅ ORJİNAL: Tüm gruplara gönder
                    'skip_aday_dns': True
                }
            
            # EXPIRED_ACCOUNT ÖZEL İŞLEM - ORJİNAL KOD GİBİ
            if error_detail.startswith("EXPIRED_ACCOUNT:"):
                try:
                    exp_info = json.loads(error_detail.replace("EXPIRED_ACCOUNT:", ""))
                    
                    self.state.gonderilen += 1
                    self.state.toplam_hata += 1
                    
                    created_at = exp_info.get('created_at', 'Bilinmiyor')
                    exp_date = exp_info.get('exp_date', 'Bilinmiyor')
                    
                    # Tarih formatlama - ORJİNAL KOD GİBİ
                    try:
                        if exp_date and exp_date != "Bilinmiyor" and str(exp_date).isdigit():
                            dt = datetime.fromtimestamp(int(exp_date))
                            exp_date = f"{dt.day}.{dt.month}.{dt.year}"
                    except:
                        pass
                        
                    try:
                        if created_at and created_at != "Bilinmiyor" and str(created_at).isdigit():
                            dt = datetime.fromtimestamp(int(created_at))
                            months = {
                                1: "Ocak", 2: "Şubat", 3: "Mart", 4: "Nisan",
                                5: "Mayıs", 6: "Haziran", 7: "Temmuz", 8: "Ağustos", 
                                9: "Eylül", 10: "Ekim", 11: "Kasım", 12: "Aralık"
                            }
                            created_at = f"{dt.day} {months.get(dt.month, '')} {dt.year}"
                    except:
                        pass
                    
                    expired_message = (
                        f"⏰ HESAP SÜRESİ DOLMUŞ ⏰\n\n"
                        f"🌍 {original_base}\n"
                        f"👤 User➢ {user}\n"
                        f"🔑 Pass➢ {(pas[:2] + '****') if pas else '****'}\n\n"
                        f"📅 Oluşturulma: {created_at}\n"
                        f"❌ Bitiş Tarihi: {exp_date}\n\n"
                        f"⚠️ Bu hesap {exp_date} tarihinde kapatıldı\n\n"
                        f"💫 @Türkei Xstream İnjecktion Team"
                    )
                    
                    self._set_error_info(original_base, f'Hesap süresi dolmuş - Bitiş: {exp_date}', 'Expired Account')
                    
                    # ✅ ORJİNAL KOD: Hesap süresi dolmuş için 3 buton
                    from orumcek_butonmodulu import buton_yoneticisi
                    keyboard = buton_yoneticisi.hata_butonlari_olustur(url_data, "expired_account")
                    
                    mesaj_paketi = {
                        'text': expired_message,
                        'parse_mode': 'HTML',
                        'url_data': url_data,
                        'keyboard': keyboard  # ✅ ORJİNAL KODDAKİ 3 BUTON
                    }
                    
                    return {
                        'status': 'error', 
                        'error': 'EXPIRED_ACCOUNT',
                        'error_detail': f'Hesap süresi dolmuş - Bitiş: {exp_date}',
                        'mesaj_paketi': mesaj_paketi,
                        'broadcast_all': True,  # ✅ ORJİNAL: Tüm gruplara gönder
                        'skip_aday_dns': True
                    }
                    
                except Exception as e:
                    print(f"❌ EXPIRED_ACCOUNT parse hatası: {e}")
                    error_detail = f"EXPIRED_ACCOUNT parse hatası: {e}"
            
            # DİĞER HATA TÜRLERİ - ORJİNAL KOD MANTIĞI
            error_config = {
                "Zaman aşımı": {
                    "text": "⏰ ZAMAN AŞIMI",
                    "adaydns_text": "Aday taraması tamamlandı: Bulunamadı",
                    "broadcast_all": False,  # ✅ ORJİNAL: Sadece scraper grubuna
                    "state_status": "Timeout",
                    "skip_aday_dns": False,
                    "message_type": "scraper"  # ✅ SCRAPER GRUBU
                },
                "Bağlantı hatası": {
                    "text": "🔌 BAĞLANTI HATASI", 
                    "adaydns_text": "Aday taraması tamamlandı: Bulunamadı",
                    "broadcast_all": False,  # ✅ ORJİNAL: Sadece scraper grubuna
                    "state_status": "Connection Error",
                    "skip_aday_dns": False,
                    "message_type": "scraper"  # ✅ SCRAPER GRUBU
                },
                "DNS çözümleme hatası": {
                    "text": "🔌 DNS ÇÖZÜMLEME HATASI",
                    "adaydns_text": "Aday taraması tamamlandı: Bulunamadı",
                    "broadcast_all": False, 
                    "state_status": "DNS Error",
                    "skip_aday_dns": False,
                    "message_type": "scraper"  # ✅ SCRAPER GRUBU
                },
                "401 Unauthorized": {
                    "text": "🔐 401 UNAUTHORIZED",
                    "adaydns_text": "Aday taraması tamamlandı: Bulunamadı",
                    "broadcast_all": False,
                    "state_status": "Auth Error",
                    "skip_aday_dns": False,
                    "message_type": "scraper"  # ✅ SCRAPER GRUBU
                },
                "SSL": {
                    "text": "🔒 SSL SERTİFİKA HATASI",
                    "adaydns_text": "Aday taraması tamamlandı: Bulunamadı",
                    "broadcast_all": False,
                    "state_status": "SSL Error",
                    "skip_aday_dns": False,
                    "message_type": "scraper"  # ✅ SCRAPER GRUBU
                }
            }
            
            error_key = "normal"
            for key in error_config:
                if key in error_detail:
                    error_key = key
                    break
            
            config = error_config.get(error_key, {
                "text": error_detail or "Sunucuya bağlanılamadı veya hesap geçersiz",
                "adaydns_text": "Aday taraması tamamlandı: Bulunamadı",
                "broadcast_all": False,  # ✅ ORJİNAL: Sadece scraper grubuna
                "state_status": "Error",
                "skip_aday_dns": False,
                "message_type": "scraper"  # ✅ SCRAPER GRUBU
            })
            
            error_text = config["text"]
            adaydns_text = config["adaydns_text"]
            broadcast_all = config["broadcast_all"]
            skip_aday_dns = config["skip_aday_dns"]
            message_type = config["message_type"]
            
            self.state.gonderilen += 1
            self.state.toplam_hata += 1
            self._set_error_info(original_base, error_detail, config["state_status"])
            
            # ✅ HATA BUTONLARI - ORJİNAL KODDA SCRAPER İÇİN 2 BUTON
            from orumcek_butonmodulu import buton_yoneticisi
            keyboard = buton_yoneticisi.hata_butonlari_olustur(url_data, message_type)
            
            mesaj_paketi = {
                'text': message_formatter.build_error_message(
                    original_base, user, pas, error_text, adaydns_text
                ),
                'parse_mode': 'HTML',
                'url_data': url_data,
                'keyboard': keyboard  # ✅ ORJİNAL KODDAKİ BUTONLAR
            }
            
            return {
                'status': 'error', 
                'error': error_text,
                'error_detail': error_detail,
                'mesaj_paketi': mesaj_paketi,
                'broadcast_all': broadcast_all,
                'skip_aday_dns': skip_aday_dns,
                'message_type': message_type  # ✅ GRUP TİPİ
            }
            
        except Exception as e:
            self.state.gonderilen += 1
            self.state.toplam_hata += 1
            self._set_error_info(original_base, f'Hata işleme hatası: {str(e)}', 'Error')
            
            # FALLBACK MESAJ
            url_data = {
                'base_url': original_base,
                'username': user,
                'password': pas,
                'm3u_link': original_base + f"/get.php?username={user}&password={pas}&type=m3u_plus"
            }
            
            from orumcek_butonmodulu import buton_yoneticisi
            keyboard = buton_yoneticisi.hata_butonlari_olustur(url_data, "scraper")
            
            return {
                'status': 'error', 
                'error': str(e),
                'error_detail': f'Hata işleme hatası: {str(e)}',
                'mesaj_paketi': {
                    'text': f"❌ Hata: {str(e)}",
                    'parse_mode': 'HTML',
                    'keyboard': keyboard
                },
                'broadcast_all': False,
                'skip_aday_dns': False,
                'message_type': "scraper"
            }

    def _create_expired_message(self, original_base, user, pas, exp_info):
        """ORJİNAL KODDAKİ HESAP SÜRESİ DOLMUŞ MESAJI"""
        created_at = exp_info.get('created_at', 'Bilinmiyor')
        exp_date = exp_info.get('exp_date', 'Bilinmiyor')
        
        # Tarih formatlama
        try:
            if exp_date and exp_date != "Bilinmiyor" and str(exp_date).isdigit():
                dt = datetime.fromtimestamp(int(exp_date))
                exp_date = f"{dt.day}.{dt.month}.{dt.year}"
        except:
            pass
            
        try:
            if created_at and created_at != "Bilinmiyor" and str(created_at).isdigit():
                dt = datetime.fromtimestamp(int(created_at))
                months = {
                    1: "Ocak", 2: "Şubat", 3: "Mart", 4: "Nisan",
                    5: "Mayıs", 6: "Haziran", 7: "Temmuz", 8: "Ağustos", 
                    9: "Eylül", 10: "Ekim", 11: "Kasım", 12: "Aralık"
                }
                created_at = f"{dt.day} {months.get(dt.month, '')} {dt.year}"
        except:
            pass
        
        return f"""⏰ HESAP SÜRESİ DOLMUŞ ⏰

🌍 {original_base}
👤 User➢ {user}
🔑 Pass➢ {(pas[:2] + '****') if pas else '****'}

📅 Oluşturulma: {created_at}
❌ Bitiş Tarihi: {exp_date}

⚠️ Bu hesap {exp_date} tarihinde kapatıldı

💫 @Türkei Xstream İnjecktion Team"""

    def handle_successful_url(self, original_base, info, user, pas, original_url):
        """BAŞARILI URL İŞLEME - MESSAGE_FORMATTER KULLANARAK"""
        try:
            # DEBUG: Başlangıç
            print(f"🟢 handle_successful_url BAŞLADI: {original_base}")
            
            # Kategori bilgilerini al
            categories = info.get('kategori_listesi', info.get('categories', []))
            print(f"📋 Kategori sayısı: {len(categories)}")
            
            # İlk kategori kontrolü için
            first_category = categories[0] if categories else ""
            
            # INFO'YU ENHANCE ET - MESSAGE_FORMATTER İÇİN GEREKLİ ALANLAR
            enhanced_info = info.copy()
            
            # Kategori bilgilerini set et
            if 'kategori_listesi' not in enhanced_info:
                enhanced_info['kategori_listesi'] = categories
            if 'gorunen_kategoriler' not in enhanced_info:
                enhanced_info['gorunen_kategoriler'] = categories[:8]
            
            # Sayısal değerleri set et
            if 'kanalsayisi' not in enhanced_info:
                enhanced_info['kanalsayisi'] = str(info.get('total_available_channels', 0))
            if 'kanalsayisi_int' not in enhanced_info:
                enhanced_info['kanalsayisi_int'] = info.get('total_available_channels', 0)
            if 'filmsayisi' not in enhanced_info:
                enhanced_info['filmsayisi'] = str(info.get('available_movies', 0))
            if 'dizisayisi' not in enhanced_info:
                enhanced_info['dizisayisi'] = str(info.get('available_series', 0))
            
            # Diğer alanlar (MESSAGE_FORMATTER İÇİN GEREKLİ)
            if 'status' not in enhanced_info:
                enhanced_info['status'] = info.get('user_info', {}).get('status', 'Active')
            if 'exp_date' not in enhanced_info:
                enhanced_info['exp_date'] = info.get('exp_date', 'Bilinmiyor')
            if 'created_at' not in enhanced_info:
                enhanced_info['created_at'] = info.get('created_at', 'Bilinmiyor')
            if 'active_cons' not in enhanced_info:
                enhanced_info['active_cons'] = info.get('user_info', {}).get('active_cons', '0')
            if 'max_connections' not in enhanced_info:
                enhanced_info['max_connections'] = info.get('user_info', {}).get('max_connections', '1')
            if 'ip' not in enhanced_info:
                enhanced_info['ip'] = info.get('ip_address', 'Bilinmiyor')
            if 'country_name' not in enhanced_info:
                enhanced_info['country_name'] = info.get('country_name', 'Türkiye')
            if 'country_code' not in enhanced_info:
                enhanced_info['country_code'] = info.get('country_code', 'TR')
            if 'isp' not in enhanced_info:
                enhanced_info['isp'] = info.get('isp', 'Bilinmiyor')
            if 'realm' not in enhanced_info:
                enhanced_info['realm'] = original_base
            if 'port' not in enhanced_info:
                enhanced_info['port'] = info.get('server_info', {}).get('port', '')
            if 'message' not in enhanced_info:
                enhanced_info['message'] = info.get('user_info', {}).get('message', '')
            if 'form' not in enhanced_info:
                enhanced_info['form'] = info.get('user_info', {}).get('allowed_output_formats', ['m3u8', 'ts'])
            if 'days_left' not in enhanced_info:
                enhanced_info['days_left'] = info.get('days_left')
            
            # Feed bilgilerini ekle
            if 'feed_count_int' not in enhanced_info:
                enhanced_info['feed_count_int'] = info.get('feed_count_int', 0)
            if 'feed_ratio' not in enhanced_info:
                enhanced_info['feed_ratio'] = info.get('feed_ratio', 0.0)
            
            # YASAKLI KATEGORİ KONTROLÜ
            host = URLProcessor.extract_hostname(original_base)
            if yasakli_kategori_var_mi([first_category], None, host):
                print(f"🚫 Yasaklı kategori tespit edildi: {first_category}")
                if host:
                    yasakli_oge_ekle(host, "kelime")
                self.state.engellenen_msg += 1
                self._set_error_info(original_base, 'Yasaklı kategori tespit edildi', 'Engellendi')
                return {'status': 'blocked', 'reason': 'Yasaklı kategori'}
            
            # ✅✅✅ BENZER DNS TESPİTİ - ORJİNAL KOD MANTIĞI
            detected_dns_list = []
            detected_count = 0
            
            try:
                print(f"🔍 Benzer DNS aranıyor... Kategoriler: {len(categories)}")
                
                # ORJİNAL KODDAKİ benzer_dns_islemleri fonksiyonunu çağır
                detected_dns_list = benzer_dns_islemleri('bul',
                    kategoriler=categories,
                    mevcut_alan=original_base
                )
                
                detected_count = len(detected_dns_list)
                print(f"✅ Tespit edilen DNS: {detected_count} adet")
                
                if detected_count > 0:
                    print(f"📋 İlk 3 DNS: {detected_dns_list[:3]}")
                    
                    # STATE'i güncelle
                    self.state.dns_list = detected_dns_list
                    self.state.tespit_edilen_benzer_sayisi = detected_count
                    
                    # INFO'YA EKLE (AI yorum için)
                    enhanced_info['detected_similar_count'] = detected_count
                    
            except Exception as e:
                print(f"❌ Benzer DNS tespit hatası: {e}")
                detected_dns_list = []
                detected_count = 0
                self.state.dns_list = []
                self.state.tespit_edilen_benzer_sayisi = 0
            
            # ✅ SAYACI ARTIR
            self.state.gonderilen += 1
            print(f"📊 Gönderilen sayaç: {self.state.gonderilen}")
            
            # ÇOKLU BAĞLANTI KONTROLÜ
            try:
                max_connections = int(re.sub(r'\D', '', str(enhanced_info.get('max_connections') or "0"))) or 0
            except:
                max_connections = 0
            
            # ✅✅✅ MESSAGE_FORMATTER İLE MESAJ HAZIRLA
            try:
                from orumcek_mesajbicimleri import message_formatter
                print(f"🔧 MessageFormatter import edildi")
                
                # MESAJI OLUŞTUR
                full_message_text = message_formatter.build_success_message(
                    original_base=original_base,
                    info=enhanced_info,  # Enhanced info
                    user=user,
                    pas=pas,
                    detected_dns_list=detected_dns_list,  # TESPİT EDİLEN DNS
                    detected_count=detected_count         # TESPİT EDİLEN SAYISI
                )
                
                print(f"✅ Mesaj oluşturuldu. Uzunluk: {len(full_message_text)} karakter")
                
                # Mesaj paketini oluştur
                mesaj_paketi = {
                    'text': full_message_text,
                    'parse_mode': 'HTML',
                    'url_data': {
                        'base_url': original_base,
                        'username': user,
                        'password': pas,
                        'detected_dns_list': detected_dns_list,
                        'detected_count': detected_count
                    }
                }
                
            except ImportError as e:
                print(f"❌ MessageFormatter import hatası: {e}")
                return {'status': 'error', 'error': f'MessageFormatter import hatası: {e}'}
            except Exception as e:
                print(f"❌ Mesaj oluşturma hatası: {e}")
                return {'status': 'error', 'error': f'Mesaj oluşturma hatası: {e}'}
            
            # BUTONLARI OLUŞTUR
            try:
                from orumcek_butonmodulu import buton_yoneticisi
                url_data = {
                    'base_url': original_base,
                    'username': user,
                    'password': pas,
                    'm3u_link': original_base + f"/get.php?username={user}&password={pas}&type=m3u_plus",
                    'categories': categories,
                    'detected_dns_list': detected_dns_list,
                    'detected_count': detected_count
                }
                
                keyboard = buton_yoneticisi.basari_butonlari_olustur(url_data, max_connections)
                mesaj_paketi['keyboard'] = keyboard
                print(f"✅ Butonlar oluşturuldu")
                
            except Exception as e:
                print(f"❌ Buton oluşturma hatası: {e}")
                mesaj_paketi['keyboard'] = []
            
            # TELEGRAM'A GÖNDER
            if self.telegram_sender.parent_widget:
                self.telegram_sender.reset_group_status()
            
            print(f"📤 Telegram'a gönderiliyor...")
            results = self.telegram_sender.send_to_groups(
                message_data=mesaj_paketi,
                max_connections=max_connections
            )
            
            print(f"✅ Telegram gönderim tamamlandı: {len(results)} grup")
            
            return {
                'status': 'success',
                'message': 'Gruplara gönderildi',
                'telegram_result': results,
                'categories': categories,
                'similar_dns_count': detected_count,
                'max_connections': max_connections,
                'detected_dns_list': detected_dns_list
            }
            
        except Exception as e:
            error_msg = f'Başarılı işleme hatası: {str(e)}'
            print(f"❌ {error_msg}")
            self._set_error_info(original_base, error_msg, 'Error')
            return {'status': 'error', 'error': str(e)}

    def send_to_telegram_groups(self, original_base, info, user, pas, original_url, max_connections=1):
        """TELEGRAM GRUPLARINA GÖNDER - DÜZELTİLMİŞ"""
        try:
            # MESAJ FORMATLAYICI İLE MESAJ HAZIRLA
            mesaj_paketi = mesaj_formatlayici.basarili_mesaj_hazirla(
                original_base, info, user, pas, 
                self.state.dns_list or [], 
                self.state.tespit_edilen_benzer_sayisi or 0
            )
            
            # Eğer butonlar oluşturulmamışsa, manuel olarak oluştur
            if not mesaj_paketi.get('keyboard'):
                url_data = {
                    'base_url': original_base,
                    'username': user,
                    'password': pas,
                    'm3u_link': original_base + f"/get.php?username={user}&password={pas}&type=m3u_plus"
                }
                
                from orumcek_butonmodulu import buton_yoneticisi
                keyboard = buton_yoneticisi.basari_butonlari_olustur(url_data, max_connections)
                mesaj_paketi['keyboard'] = keyboard
            
            # ✅ DÜZELTME: GRUP DURUMLARINI SIFIRLA
            if self.telegram_sender.parent_widget:
                self.telegram_sender.reset_group_status()
            
            # ÇOKLU BAĞLANTI KONTROLLÜ GÖNDERİM
            results = self.telegram_sender.send_to_groups(
                message_data=mesaj_paketi,
                max_connections=max_connections
            )
            
            # ✅ DÜZELTME: GRUP DURUMLARINI GÜNCELLE - TELEGRAM SENDER ZATEN YAPIYOR
            # Bu kısım gereksiz, TelegramSender zaten durumları güncelliyor
            
            print(f"✅ Telegram gönderim tamamlandı: {len(results)} grup")
            return results
            
        except Exception as e:
            print(f"❌ Telegram mesaj hazırlama hatası: {e}")
            return {}

    def _set_error_info(self, dns, detail, status):
        """Hata bilgisini ayarla - DÜZELTİLMİŞ"""
        try:
            self.state.last_error_info = {
                'dns': dns,
                'detail': detail,
                'status': status
            }
        except Exception as e:
            print(f"❌ Hata bilgisi ayarlama hatası: {e}")

# =============================================================================
# ADAY DNS KONTROL SİSTEMİ - ORJİNAL KODA UYGUN
# =============================================================================

# orumcek_module.py - TAM AdayDNSProcessor SINIFI
class AdayDNSProcessor:
    def __init__(self, state):
        self.state = state
        self.is_running = True
        
    def check_aday_dns(self, user, pas, original_base, max_workers=8, timeout=3):
        """Aday DNS kontrolü"""
        try:
            aday_list = load_aday_dns()
            
            if not aday_list:
                self.state.aday_durum = "❌ Aday DNS listesi boş"
                return False, None, 0
                
            self.state.aday_toplam = len(aday_list)
            self.state.aday_kontrol_edilen = 0
            self.state.aday_olu = original_base
            self.state.aday_suan = ""
            self.state.aday_sonuc = None
            self.state.aday_durum = "🔄 Aday DNS kontrolü başlatıldı"
            self.state.aday_test_edilen = 0
            self.state.aday_bulunan = 0
            self.state.aday_gecerli = 0
            self.state.aday_gecersiz = 0
            self.state.aday_bekleyen = len(aday_list)
            
            found_base = None
            checked = 0
            
            for aday in aday_list:
                if not self.is_running:
                    break
                    
                if not aday.strip():
                    continue
                    
                checked += 1
                self.state.aday_kontrol_edilen = checked
                self.state.aday_suan = aday
                self.state.aday_test_edilen = checked
                self.state.aday_bekleyen = len(aday_list) - checked
                
                try:
                    # DNS'i normalize et
                    test_url = aday if aday.startswith('http') else f"http://{aday}"
                    
                    # HIZLI M3U TESTİ
                    test_info = fetch_real_m3u_info(test_url, user, pas, timeout=timeout)
                    
                    if test_info:
                        found_base = test_url
                        self.state.aday_sonuc = found_base
                        self.state.aday_bulunan += 1
                        self.state.aday_gecerli += 1
                        self.state.aday_durum = f"✅ Aday DNS bulundu: {found_base}"
                        return True, found_base, checked
                    else:
                        self.state.aday_gecersiz += 1
                        
                except Exception:
                    self.state.aday_gecersiz += 1
                    continue
                    
            if found_base is None:
                self.state.aday_sonuc = None
                self.state.aday_durum = f"❌ Uygun Aday DNS bulunamadı ({checked} test edildi)"
            else:
                self.state.aday_durum = f"✅ Aday DNS bulundu: {found_base}"
                
            self.state.aday_bekleyen = 0
            return found_base is not None, found_base, checked
            
        except Exception as e:
            error_msg = f"❌ Aday DNS hatası: {str(e)}"
            self.state.aday_durum = error_msg
            self.state.aday_bekleyen = 0
            return False, None, 0

    def stop(self):
        """Aday DNS kontrolünü durdur"""
        self.is_running = False


class ScanSettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🔧 Tarama Ayarları")
        self.setModal(True)
        self.resize(450, 500)  # DAHA KÜÇÜK BOYUT
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(6)  # DAHA AZ BOŞLUK
        layout.setContentsMargins(10, 10, 10, 10)  # DAHA KÜÇÜK MARGIN
        
        # Ana başlık - DAHA KÜÇÜK
        title = QLabel("Tarama Ön İşlem Ayarları")
        title.setStyleSheet("""
            QLabel {
                font-size: 14px; 
                font-weight: bold; 
                color: white;
                padding: 8px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3498db, stop:1 #2ecc71);
                border-radius: 6px;
                text-align: center;
            }
        """)
        layout.addWidget(title)
        
        # İŞLEM SEÇENEKLERİ GRUBU - DAHA KOMPAKT
        settings_group = QGroupBox("🛠️ İşlem Seçenekleri")
        settings_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #2c3e50;
                border: 1px solid #3498db;
                border-radius: 6px;
                margin-top: 5px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 6px 0 6px;
                background-color: #ecf0f1;
                color: #2c3e50;
            }
        """)
        settings_layout = QVBoxLayout()
        settings_layout.setSpacing(4)  # DAHA AZ BOŞLUK
        
        self.check_duplicate = QCheckBox("❌ Duplicate Kontrolü")
        self.check_duplicate.setChecked(True)
        self.check_duplicate.setStyleSheet("font-size: 11px; padding: 6px;")
        
        self.check_banned = QCheckBox("🚫 Yasaklı Kelime Kontrolü") 
        self.check_banned.setChecked(True)
        self.check_banned.setStyleSheet("font-size: 11px; padding: 6px;")
        
        self.check_group_leader = QCheckBox("👑 Grup Lideri Değişimi")
        self.check_group_leader.setChecked(True)
        self.check_group_leader.setStyleSheet("font-size: 11px; padding: 6px;")
        
        self.check_similar_dns = QCheckBox("🔍 Benzer DNS Kontrolü")
        self.check_similar_dns.setChecked(True)
        self.check_similar_dns.setStyleSheet("font-size: 11px; padding: 6px;")
        
        self.check_aday_dns = QCheckBox("🎯 Aday DNS Kontrolü")
        self.check_aday_dns.setChecked(True)
        self.check_aday_dns.setStyleSheet("font-size: 11px; padding: 6px;")
        
        settings_layout.addWidget(self.check_duplicate)
        settings_layout.addWidget(self.check_banned)
        settings_layout.addWidget(self.check_group_leader)
        settings_layout.addWidget(self.check_similar_dns)
        settings_layout.addWidget(self.check_aday_dns)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # ADAY DNS AYARLARI GRUBU - DAHA KOMPAKT
        aday_group = QGroupBox("🎯 Aday DNS")
        aday_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #2c3e50;
                border: 1px solid #e74c3c;
                border-radius: 6px;
                margin-top: 5px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 6px 0 6px;
                background-color: #fadbd8;
                color: #2c3e50;
            }
        """)
        aday_layout = QFormLayout()
        aday_layout.setVerticalSpacing(4)  # DAHA AZ BOŞLUK
        
        self.aday_workers = QSpinBox()
        self.aday_workers.setRange(1, 50)  # Range'i 50'ye çıkar
        self.aday_workers.setValue(25)  # ✅ Varsayılan değeri 25 yap
        self.aday_workers.setSuffix(" bot")
        self.aday_workers.setStyleSheet("padding: 4px; font-size: 10px;")
        
        self.aday_timeout = QSpinBox()
        self.aday_timeout.setRange(1, 10)
        self.aday_timeout.setValue(3)
        self.aday_timeout.setSuffix(" sn")
        self.aday_timeout.setStyleSheet("padding: 4px; font-size: 10px;")
        
        aday_layout.addRow("Paralel Bot:", self.aday_workers)
        aday_layout.addRow("Timeout:", self.aday_timeout)
        
        aday_group.setLayout(aday_layout)
        layout.addWidget(aday_group)
        
        # İLERLEME AYARLARI GRUBU - DAHA KOMPAKT
        progress_group = QGroupBox("⚡ İlerleme")
        progress_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                font-size: 12px;
                color: #2c3e50;
                border: 1px solid #f39c12;
                border-radius: 6px;
                margin-top: 5px;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 6px 0 6px;
                background-color: #fdebd0;
                color: #2c3e50;
            }
        """)
        progress_layout = QFormLayout()
        progress_layout.setVerticalSpacing(4)
        
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 2000)
        self.delay_spin.setValue(300)
        self.delay_spin.setSuffix(" ms")
        self.delay_spin.setStyleSheet("padding: 4px; font-size: 10px;")
        
        self.batch_size = QSpinBox()
        self.batch_size.setRange(0, 100)  # ✅ 0 değerini ekle
        self.batch_size.setValue(0)  # ✅ Varsayılan değeri 0 yap
        self.batch_size.setSuffix(" URL")
        self.batch_size.setStyleSheet("padding: 4px; font-size: 10px;")
        
        progress_layout.addRow("Gecikme:", self.delay_spin)
        progress_layout.addRow("Toplu İşlem:", self.batch_size)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # BİLGİLENDİRME - DAHA KISA
        info_text = QLabel("""
        <b>🎯 Aday DNS:</b> 8 bot ile hızlı tarama<br>
        <b>⚡ Performans:</b> Optimize edilmiş ayarlar<br>
        <b>⏰ Timeout:</b> DNS başına 3 saniye
        """)
        info_text.setStyleSheet("""
            QLabel {
                font-size: 9px; 
                padding: 6px; 
                background-color: #f8f9fa; 
                border-radius: 4px;
                color: #2c3e50;
            }
        """)
        info_text.setWordWrap(True)
        layout.addWidget(info_text)
        
        # BUTONLAR - DAHA KÜÇÜK
        button_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 BAŞLAT")
        self.start_btn.setMinimumHeight(35)  # DAHA KÜÇÜK
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                font-weight: bold;
                padding: 8px;
                border: none;
                border-radius: 5px;
                font-size: 12px;
            }
            QPushButton:hover { background-color: #2ecc71; }
        """)
        self.start_btn.clicked.connect(self.accept)
        
        self.cancel_btn = QPushButton("❌ İPTAL")
        self.cancel_btn.setMinimumHeight(35)  # DAHA KÜÇÜK
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                font-weight: bold;
                padding: 8px;
                border: none;
                border-radius: 5px;
                font-size: 12px;
            }
            QPushButton:hover { background-color: #c0392b; }
        """)
        self.cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def get_settings(self):
        return {
            'check_duplicate': self.check_duplicate.isChecked(),
            'check_banned': self.check_banned.isChecked(),
            'check_group_leader': self.check_group_leader.isChecked(),
            'check_similar_dns': self.check_similar_dns.isChecked(),
            'check_aday_dns': self.check_aday_dns.isChecked(),
            'aday_workers': self.aday_workers.value(),
            'aday_timeout': self.aday_timeout.value(),
            'delay': self.delay_spin.value(),
            'batch_size': self.batch_size.value(),
        }

# orumcek_module.py - TAM FileScanThread SINIFI
class FileScanThread(QThread):
    log_signal = pyqtSignal(str, str)
    progress_signal = pyqtSignal(dict)
    finished = pyqtSignal()
    
    def __init__(self, urls, state, options, bot_token, chat_ids, source_file=None, parent_widget=None):
        super().__init__()
        self.urls = urls
        self.state = state
        self.options = options
        self.bot_token = bot_token
        self.chat_ids = chat_ids
        self.source_file = source_file
        self.parent_widget = parent_widget
        self.is_running = True
        self.processed = 0
        self.errors = 0
        self.success_count = 0
        self.aday_processor = AdayDNSProcessor(state)
        
        # Processor'ı parent ile bağla
        self.processor = M3UProcessor(state, bot_token, chat_ids, parent_widget)
    
    def stop(self):
        """Thread'i durdur"""
        self.is_running = False
        if hasattr(self, 'aday_processor'):
            self.aday_processor.stop()
    
    def remove_processed_url(self, url):
        """İşlenen URL'yi dosyadan sil"""
        try:
            if not self.source_file or not os.path.exists(self.source_file):
                return
                
            with open(self.source_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [ln.rstrip("\n") for ln in f if ln.strip()]
            
            # URL'yi dosyadan kaldır
            new_lines = [ln for ln in lines if ln.strip() != url.strip()]
            
            # Dosyayı güncelle
            with open(self.source_file, 'w', encoding='utf-8', errors='ignore') as f:
                f.write("\n".join(new_lines))
                
            self.log_signal.emit(f"🗑️ Dosyadan silindi: {url}", "info")
            
        except Exception as e:
            self.log_signal.emit(f"❌ Dosya silme hatası: {str(e)}", "error")
    
    def send_error_message(self, base, user, pas, error_detail):
        """Hata mesajını gönder"""
        try:
            # Hata mesajını message_formatter ile hazırla
            mesaj_paketi = {
                'text': message_formatter.build_error_message(
                    base, user, pas, error_detail, "Aday taraması tamamlandı: Bulunamadı"
                ),
                'parse_mode': 'HTML',
                'url_data': {
                    'base_url': base,
                    'username': user,
                    'password': pas,
                    'error': error_detail
                }
            }
            
            # Sadece scraper grubuna gönder
            scraper_group_id = -1001844205745
            
            result = self.processor.telegram_sender.send_error_message(
                scraper_group_id, 
                mesaj_paketi['text'],
                mesaj_paketi.get('url_data')
            )
            
            if result.get('ok'):
                self.log_signal.emit(f"✅ Hata mesajı gönderildi: {base}", "success")
            else:
                self.log_signal.emit(f"❌ Hata mesajı gönderilemedi: {result.get('error')}", "error")
                
        except Exception as e:
            self.log_signal.emit(f"❌ Hata mesajı gönderme hatası: {str(e)}", "error")
    
    def run(self):
        try:
            total = len(self.urls)
            
            if self.parent_widget and hasattr(self.parent_widget, 'reset_group_statuses'):
                self.parent_widget.reset_group_statuses()
            
            duplicated_urls = list(dict.fromkeys(self.urls))
            random.shuffle(duplicated_urls)
            
            self.log_signal.emit(f"🔀 {len(duplicated_urls)} URL random karıştırıldı", "info")
            
            while duplicated_urls and self.is_running:
                try:
                    url = duplicated_urls.pop(random.randrange(len(duplicated_urls)))
                    
                    if self.parent_widget and hasattr(self.parent_widget, 'reset_group_statuses'):
                        self.parent_widget.reset_group_statuses()
                    
                    next_url = duplicated_urls[0] if duplicated_urls else ""
                    self.progress_signal.emit({
                        'current_url': url,
                        'current_stage': 'M3U bilgileri alınıyor',
                        'next_url': next_url,
                        'processed': self.processed,
                        'total': total,
                        'errors': self.errors,
                        'success': self.success_count,
                        'remaining': len(duplicated_urls)
                    })
                    
                    result = self.processor.process_url(url)
                    
                    if result['status'] == 'success':
                        self.success_count += 1
                        self.log_signal.emit(f"✅ GRUPLARA GÖNDERİLDİ: {url}", "success")
                        
                    elif result['status'] == 'blocked':
                        self.log_signal.emit(f"🚫 ENGELLENDİ: {url}", "warning")
                        
                    elif result['status'] == 'error':
                        self.errors += 1
                        error_detail = result.get('error_detail', result.get('error', ''))
                        
                        mesaj_paketi = result.get('mesaj_paketi')
                        if mesaj_paketi:
                            try:
                                target_groups = []
                                
                                if error_detail == "ACCOUNT_DISABLED" or result.get('error') == "ACCOUNT_DISABLED":
                                    self.log_signal.emit(f"⏰ HESAP KAPATILMIŞ: {url}", "warning")
                                    target_groups = [-1001948263686, -1001844205745]
                                
                                elif "EXPIRED_ACCOUNT" in error_detail or result.get('error') == "EXPIRED_ACCOUNT":
                                    self.log_signal.emit(f"⏰ HESAP SÜRESİ DOLMUŞ: {url}", "warning")
                                    target_groups = [-1001948263686, -1001844205745]
                                
                                else:
                                    self.log_signal.emit(f"❌ HATA: {url} - {error_detail}", "error")
                                    target_groups = [-1001844205745]
                                
                                success_count = 0
                                for chat_id in target_groups:
                                    try:
                                        if self.parent_widget and hasattr(self.parent_widget, 'state'):
                                            self.parent_widget.state.message_status[chat_id] = {
                                                'state': 'gonderiliyor',
                                                'ts': None
                                            }
                                        
                                        send_result = self.processor.telegram_sender._send_message(chat_id, mesaj_paketi)
                                        
                                        if send_result.get('ok'):
                                            if self.parent_widget and hasattr(self.parent_widget, 'state'):
                                                self.parent_widget.state.message_status[chat_id] = {
                                                    'state': 'gonderildi',
                                                    'ts': datetime.now().strftime('%H:%M:%S')
                                                }
                                            success_count += 1
                                        else:
                                            if self.parent_widget and hasattr(self.parent_widget, 'state'):
                                                self.parent_widget.state.message_status[chat_id] = {
                                                    'state': 'hata',
                                                    'ts': datetime.now().strftime('%H:%M:%S')
                                                }
                                        
                                        time.sleep(1)
                                        
                                    except Exception:
                                        if self.parent_widget and hasattr(self.parent_widget, 'state'):
                                            self.parent_widget.state.message_status[chat_id] = {
                                                'state': 'hata',
                                                'ts': datetime.now().strftime('%H:%M:%S')
                                            }
                                
                                if success_count > 0:
                                    self.log_signal.emit(f"✅ Mesaj {success_count} gruba gönderildi", "success")
                                else:
                                    self.log_signal.emit(f"❌ Mesaj gönderilemedi", "error")
                                    
                            except Exception as e:
                                self.log_signal.emit(f"❌ Mesaj gönderme hatası: {str(e)}", "error")
                        
                        elif self.options.get('check_aday_dns', True) and not result.get('skip_aday_dns', False):
                            parsed = urlparse(url)
                            qs = parse_qs(parsed.query)
                            user = qs.get('username', [None])[0] or ""
                            pas = qs.get('password', [None])[0] or ""
                            base = URLProcessor.get_base_url_only(url)
                            
                            if user and pas and base:
                                self.log_signal.emit(f"🔍 ADAY DNS KONTROLÜ BAŞLATILIYOR: {base}", "info")
                                
                                self.state.current_processing_stage = "🔍 Aday DNS kontrol ediliyor"
                                self.progress_signal.emit({
                                    'current_stage': '🔍 Aday DNS kontrol ediliyor'
                                })
                                
                                max_workers = self.options.get('aday_workers', 8)
                                timeout = self.options.get('aday_timeout', 3)
                                
                                found, found_base, checked = self.aday_processor.check_aday_dns(
                                    user, pas, base, max_workers, timeout
                                )
                                
                                if found:
                                    self.log_signal.emit(f"✅ ADAY DNS BULUNDU: {found_base}", "success")
                                    
                                    new_url = found_base + f"/get.php?username={user}&password={pas}&type=m3u_plus"
                                    
                                    self.state.current_processing_stage = "🔄 Aday DNS ile tekrar deneniyor"
                                    self.progress_signal.emit({
                                        'current_stage': '🔄 Aday DNS ile tekrar deneniyor'
                                    })
                                    
                                    new_result = self.processor.process_url(new_url)
                                    if new_result['status'] == 'success':
                                        self.success_count += 1
                                        self.log_signal.emit(f"✅ ADAY DNS İLE GÖNDERİLDİ: {found_base}", "success")
                                    else:
                                        error_reason = new_result.get('reason', 'Bilinmeyen hata')
                                        self.log_signal.emit(f"❌ ADAY DNS İLE GÖNDERİLEMEDİ: {found_base} - {error_reason}", "error")
                                        
                                        if result.get('mesaj_paketi'):
                                            send_result = self.processor.telegram_sender._send_message(
                                                -1001844205745,
                                                result['mesaj_paketi']
                                            )
                                            if send_result.get('ok'):
                                                self.log_signal.emit(f"✅ Hata mesajı scraper grubuna gönderildi", "success")
                                            else:
                                                self.log_signal.emit(f"❌ Hata mesajı gönderme hatası", "error")
                                else:
                                    self.log_signal.emit(f"❌ UYGUN ADAY DNS BULUNAMADI ({checked} DNS test edildi)", "warning")
                                    
                                    if result.get('mesaj_paketi'):
                                        send_result = self.processor.telegram_sender._send_message(
                                            -1001844205745,
                                            result['mesaj_paketi']
                                        )
                                        if send_result.get('ok'):
                                            self.log_signal.emit(f"✅ Hata mesajı scraper grubuna gönderildi", "success")
                                        else:
                                            self.log_signal.emit(f"❌ Hata mesajı gönderme hatası", "error")
                        else:
                            # Diğer hatalar için log
                            self.log_signal.emit(f"❌ HATA: {url} - {error_detail}", "error")
                            
                            if not result.get('skip_aday_dns', False) and result.get('mesaj_paketi'):
                                try:
                                    scraper_group_id = -1001844205745
                                    send_result = self.processor.telegram_sender._send_message(
                                        scraper_group_id,
                                        result['mesaj_paketi']
                                    )
                                    if send_result.get('ok'):
                                        self.log_signal.emit(f"✅ Hata mesajı scraper grubuna gönderildi", "success")
                                    else:
                                        self.log_signal.emit(f"❌ Hata mesajı gönderme hatası", "error")
                                except Exception as send_e:
                                    self.log_signal.emit(f"❌ Hata mesajı gönderme hatası: {send_e}", "error")
                    
                    self.processed += 1
                    
                    if self.source_file:
                        self.remove_processed_url(url)
                    
                    self.state.remaining_urls = len(duplicated_urls)
                    
                    self.progress_signal.emit({
                        'processed': self.processed,
                        'total': total,
                        'errors': self.errors,
                        'success': self.success_count,
                        'remaining': len(duplicated_urls)
                    })
                    
                    delay = self.options.get('delay', 300)
                    time.sleep(delay / 1000.0)
                    
                except Exception as e:
                    self.errors += 1
                    self.processed += 1
                    self.log_signal.emit(f"❌ İŞLEM HATASI: {str(e)}", "error")
            
            if self.is_running:
                self.log_signal.emit(
                    f"✅ Tarama tamamlandı! Gönderilen: {self.success_count}/{total}", 
                    "success"
                )
            else:
                self.log_signal.emit("⏹️ Tarama durduruldu", "warning")
                
        except Exception as e:
            self.log_signal.emit(f"❌ Tarama hatası: {str(e)}", "error")
        finally:
            self.finished.emit()

# =============================================================================
# ANA UYGULAMA WIDGET'I - TAM VE EKSİKSİZ
# =============================================================================

class OrumcekWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.state = AppState()
        self.bot_token = BOT_TOKEN
        self.chat_ids = CHAT_IDS
        self.telegram_sender = TelegramSender(self.bot_token, self.chat_ids)
        # ✅ DÜZELTME: set_parent_widget metodunu kullan
        self.telegram_sender.set_parent_widget(self)
        self.scan_thread = None
        self.listener_thread = None
        self.selected_json_file = TESPIT_JSON
        self.current_tab = "file"
        self.init_ui()
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status_display)
        self.update_timer.start(1000)
        
        self.load_initial_data()
        self.setup_navigation()
        
    def reset_group_statuses(self):
        """Tüm grup durumlarını sıfırla (sarı/bekleme durumuna getir)"""
        try:
            for chat_id in self.chat_ids:
                self.state.message_status[chat_id] = {
                    'state': 'bekle',
                    'ts': None
                }
            print("🔄 Grup durumları sıfırlandı (sarı)")
        except Exception as e:
            print(f"❌ Grup durumları sıfırlama hatası: {e}")
            
    def setup_navigation(self):
        # Navigasyon bağlantıları
        self.sidebar.nav_buttons['file'].clicked.connect(lambda: self.show_tab('file'))
        self.sidebar.nav_buttons['group'].clicked.connect(lambda: self.show_tab('group'))
        self.sidebar.nav_buttons['url'].clicked.connect(lambda: self.show_tab('url'))
        self.sidebar.nav_buttons['settings'].clicked.connect(lambda: self.show_tab('settings'))
        
        # İlk butonu seçili yap
        self.sidebar.nav_buttons['file'].setChecked(True)
    
    def show_tab(self, tab_key):
        # Tüm butonların seçimini kaldır
        for btn in self.sidebar.nav_buttons.values():
            btn.setChecked(False)
        
        # Seçilen butonu işaretle
        self.sidebar.nav_buttons[tab_key].setChecked(True)
        
        # İlgili sayfayı göster
        self.stacked_widget.setCurrentIndex(['file', 'group', 'url', 'settings'].index(tab_key))
        self.current_tab = tab_key
    
    def load_initial_data(self):
        try:
            if GITHUB_REPO and GITHUB_TOKEN:
                gh_load_all()
            
            self.state.yasakli_kelimeler = yasakli_kelimeleri_yukle()
            self.state.yasakli_kategoriler = yasakli_kategorileri_yukle()
            self.state.tespit_edilen = load_tespit_edilen_gruplar()
            
            self.log_message("✅ Sistem başlatıldı - Tüm veriler yüklendi", "success")
            self.log_message("✅ Modern arayüz yüklendi", "success")
            
        except Exception as e:
            self.log_message(f"❌ Başlangıç yükleme hatası: {str(e)}", "error")
    
    def init_ui(self):
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sol sidebar
        self.sidebar = ModernSidebar(self)
        main_layout.addWidget(self.sidebar)
        
        # Ana içerik alanı
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(10, 10, 10, 10)
        content_layout.setSpacing(8)
        
        # Üst başlık
        header = QLabel("🕷️ ÖRÜMCEK - GELİŞMİŞ M3U TARAYICI v3.0")
        header.setStyleSheet("""
            QLabel {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e74c3c, stop:0.5 #e67e22, stop:1 #f1c40f);
                color: white;
                font-size: 14px;
                font-weight: bold;
                padding: 8px;
                border-radius: 6px;
                text-align: center;
            }
        """)
        content_layout.addWidget(header)
        
        # Stacked widget for tabs
        self.stacked_widget = QStackedWidget()
        
        # Tab içerikleri
        self.file_tab = self.create_file_tab()
        self.group_tab = self.create_group_tab()
        self.url_tab = self.create_url_tab()
        self.settings_tab = self.create_settings_tab()
        
        self.stacked_widget.addWidget(self.file_tab)
        self.stacked_widget.addWidget(self.group_tab)
        self.stacked_widget.addWidget(self.url_tab)
        self.stacked_widget.addWidget(self.settings_tab)
        
        content_layout.addWidget(self.stacked_widget)
        
        main_layout.addWidget(content_widget, 4)
        
        # Sağ panel - DÜZELTİLMİŞ: parent=self parametresini ekleyin
        self.right_panel = RightSidePanel(self.state, self)  # <- BURAYI DÜZELTİN
        main_layout.addWidget(self.right_panel, 1)
        
        self.setLayout(main_layout)
        self.setWindowTitle("Örümcek M3U Tarayıcı v3.0 - Modern Arayüz")
        self.resize(1400, 900)
    
    def create_file_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(8)
        
        # İŞLEM BİLGİSİ KALDIRILDI - Artık ModernControlPanel'de
        
        # İşlem paneli
        self.modern_processing_panel = ModernProcessingPanel(self.state)
        layout.addWidget(self.modern_processing_panel)
        
        # Log ekranı
        log_section = QGroupBox("📝 İŞLEM KAYITLARI")
        log_layout = QVBoxLayout()
        
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFixedHeight(190)
        self.log_display.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #34495e;
                border-radius: 4px;
                font-family: 'Consolas', 'Courier New';
                font-size: 12px;
                padding: 4px;
            }
        """)
        log_layout.addWidget(self.log_display)
        
        log_section.setLayout(log_layout)
        layout.addWidget(log_section)
        
        widget.setLayout(layout)
        return widget

    def create_group_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        group_section = QGroupBox("👥 GRUP YÖNETİMİ")
        group_layout = QVBoxLayout()
        
        info_text = QLabel("Grup dinleme özelliği aktif değil")
        info_text.setStyleSheet("padding: 40px; background-color: #34495e; color: #bdc3c7; border-radius: 8px; text-align: center;")
        info_text.setAlignment(Qt.AlignCenter)
        
        group_layout.addWidget(info_text)
        group_section.setLayout(group_layout)
        layout.addWidget(group_section)
        
        widget.setLayout(layout)
        return widget

    def create_url_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        url_section = QGroupBox("🔗 TEKİL URL İŞLEME")
        url_layout = QVBoxLayout()
        
        self.url_input = QTextEdit()
        self.url_input.setPlaceholderText("""M3U URL'lerini buraya yapıştırın...
Her satıra bir URL

Örnek formatlar:
http://example.com/get.php?username=test&password=test&type=m3u_plus
http://example.com/player_api.php?username=user&password=pass
http://example.com:8080/panel_api.php?username=test&password=test""")
        self.url_input.setMaximumHeight(120)
        self.url_input.setStyleSheet("""
            QTextEdit {
                border: 1px solid #34495e;
                border-radius: 4px;
                padding: 8px;
                font-family: 'Consolas';
                font-size: 10px;
            }
        """)
        url_layout.addWidget(self.url_input)
        
        url_btn_layout = QHBoxLayout()
        
        self.scan_urls_btn = QPushButton("🚀 URL'LERİ TARA")
        self.scan_urls_btn.setStyleSheet("""
            QPushButton {
                padding: 8px;
                font-weight: bold;
                background-color: #2ecc71;
                color: white;
                border-radius: 4px;
                font-size: 11px;
            }
            QPushButton:hover { background-color: #27ae60; }
        """)
        self.scan_urls_btn.clicked.connect(self.start_url_scan)
        
        self.clear_urls_btn = QPushButton("🧹 Temizle")
        self.clear_urls_btn.setStyleSheet("""
            QPushButton {
                padding: 8px;
                background-color: #95a5a6;
                color: white;
                border-radius: 4px;
                font-size: 11px;
            }
            QPushButton:hover { background-color: #7f8c8d; }
        """)
        self.clear_urls_btn.clicked.connect(self.clear_urls)
        
        url_btn_layout.addWidget(self.scan_urls_btn)
        url_btn_layout.addWidget(self.clear_urls_btn)
        url_btn_layout.addStretch()
        
        url_layout.addLayout(url_btn_layout)
        url_section.setLayout(url_layout)
        layout.addWidget(url_section)
        
        self.url_log = QTextEdit()
        self.url_log.setReadOnly(True)
        self.url_log.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #34495e;
                border-radius: 4px;
                font-family: 'Consolas', 'Courier New';
                font-size: 10px;
                padding: 8px;
            }
        """)
        layout.addWidget(self.url_log)
        
        widget.setLayout(layout)
        return widget

    def create_settings_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # API Ayarları
        api_section = QGroupBox("🔑 API AYARLARI")
        api_layout = QFormLayout()
        
        self.bot_token_input = QLineEdit(BOT_TOKEN)
        self.api_id_input = QLineEdit(str(API_ID))
        self.api_hash_input = QLineEdit(API_HASH)
        self.session_name_input = QLineEdit(SESSION_NAME)
        
        # Stil uygula
        for input_field in [self.bot_token_input, self.api_id_input, self.api_hash_input, self.session_name_input]:
            input_field.setStyleSheet("""
                QLineEdit {
                    padding: 6px;
                    border: 1px solid #34495e;
                    border-radius: 3px;
                    background-color: #2c3e50;
                    color: white;
                    font-size: 11px;
                }
            """)
        
        api_layout.addRow("Bot Token:", self.bot_token_input)
        api_layout.addRow("API ID:", self.api_id_input)
        api_layout.addRow("API Hash:", self.api_hash_input)
        api_layout.addRow("Session Name:", self.session_name_input)
        
        api_section.setLayout(api_layout)
        layout.addWidget(api_section)
        
        # GitHub Ayarları
        github_section = QGroupBox("🌐 GITHUB AYARLARI")
        github_layout = QFormLayout()
        
        self.github_repo_input = QLineEdit(GITHUB_REPO)
        self.github_token_input = QLineEdit(GITHUB_TOKEN)
        self.github_branch_input = QLineEdit(GITHUB_BRANCH)
        
        for input_field in [self.github_repo_input, self.github_token_input, self.github_branch_input]:
            input_field.setStyleSheet("""
                QLineEdit {
                    padding: 6px;
                    border: 1px solid #34495e;
                    border-radius: 3px;
                    background-color: #2c3e50;
                    color: white;
                    font-size: 11px;
                }
            """)
        
        github_layout.addRow("Repository:", self.github_repo_input)
        github_layout.addRow("Token:", self.github_token_input)
        github_layout.addRow("Branch:", self.github_branch_input)
        
        github_section.setLayout(github_layout)
        layout.addWidget(github_section)
        
        # Butonlar
        settings_buttons = QHBoxLayout()
        
        self.save_settings_btn = QPushButton("💾 Ayarları Kaydet")
        self.save_settings_btn.setStyleSheet("""
            QPushButton {
                padding: 8px;
                background-color: #27ae60;
                color: white;
                font-weight: bold;
                border-radius: 4px;
                font-size: 11px;
            }
            QPushButton:hover { background-color: #2ecc71; }
        """)
        self.save_settings_btn.clicked.connect(self.save_settings)
        
        self.reset_settings_btn = QPushButton("🔄 Varsayılana Dön")
        self.reset_settings_btn.setStyleSheet("""
            QPushButton {
                padding: 8px;
                background-color: #f39c12;
                color: white;
                border-radius: 4px;
                font-size: 11px;
            }
            QPushButton:hover { background-color: #e67e22; }
        """)
        self.reset_settings_btn.clicked.connect(self.reset_settings)
        
        settings_buttons.addWidget(self.save_settings_btn)
        settings_buttons.addWidget(self.reset_settings_btn)
        
        layout.addLayout(settings_buttons)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Taramak için dosya seçin",
            BASE_FOLDER,
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            self.selected_file = file_path
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = [ln.strip() for ln in f if ln.strip()]
                
                file_name = os.path.basename(file_path)
                self.sidebar.file_info.setText(f"📄 {file_name}\n{len(lines)} satır\n{os.path.getsize(file_path)//1024} KB")
                
                self.log_message(f"✅ Dosya seçildi: {file_name} ({len(lines)} satır)", "success")
                
            except Exception as e:
                self.log_message(f"❌ Dosya okuma hatası: {str(e)}", "error")

    def start_file_scan(self):
        if not hasattr(self, 'selected_file'):
            self.log_message("❌ Lütfen önce dosya seçin!", "error")
            return
        
        # Ayarlar dialogunu göster
        dialog = ScanSettingsDialog(self)
        if dialog.exec_() != QDialog.Accepted:
            return
        
        settings = dialog.get_settings()
        
        try:
            # Ön işlemler
            total_changes = 0
            
            if settings['check_group_leader']:
                self.log_message("🔍 Benzer DNS kontrolü yapılıyor...", "info")
                degisen_sayisi, degisen_dnsler = benzer_dns_islemleri(
                    'degistir', 
                    source_path=self.selected_file
                )
                if degisen_sayisi > 0:
                    self.log_message(f"✅ {degisen_sayisi} satır grup lideri ile değiştirildi", "success")
                    self.state.group_leader_changed = degisen_sayisi
                    total_changes += degisen_sayisi
            
            if settings['check_duplicate'] or settings['check_banned']:
                self.log_message("🧹 Dosya temizleme işlemi yapılıyor...", "info")
                yasakli_kelimeler = yasakli_kelimeleri_yukle()
                new_total, removed_dup, removed_banned = preprocess_source_file(
                    self.selected_file, yasakli_kelimeler
                )
                
                if settings['check_duplicate'] and removed_dup > 0:
                    self.log_message(f"✅ {removed_dup} duplicate silindi", "success")
                    self.state.duplicate_removed = removed_dup
                    total_changes += removed_dup
                
                if settings['check_banned'] and removed_banned > 0:
                    self.log_message(f"✅ {removed_banned} yasaklı silindi", "success")
                    self.state.banned_removed = removed_banned
                    total_changes += removed_banned
            
            with open(self.selected_file, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [ln.strip() for ln in f if ln.strip()]
            
            self.state.total_urls = len(urls)
            self.state.remaining_urls = len(urls)
            self.state.current_source_file = self.selected_file
            
            self.log_message(f"🚀 Tarama başlatıldı: {len(urls)} URL • {total_changes} ön işlem uygulandı", "info")
            
            # ✅ GRUP DURUMLARINI SIFIRLA
            self.reset_group_statuses()
            
            # ✅ DOSYA YOLUNU VE PARENT_WIDGET'I THREAD'E VER
            self.scan_thread = FileScanThread(
                urls, 
                self.state, 
                settings,
                self.bot_token,
                self.chat_ids,
                self.selected_file,
                self
            )
            self.scan_thread.log_signal.connect(self.log_message)
            self.scan_thread.progress_signal.connect(self.update_scan_progress)
            self.scan_thread.finished.connect(self.on_scan_finished)
            self.scan_thread.start()
            
        except Exception as e:
            self.log_message(f"❌ Dosya işleme hatası: {str(e)}", "error")

    def update_scan_progress(self, data):
        processed = data.get('processed', 0)
        total = data.get('total', 0)
        errors = data.get('errors', 0)
        success = data.get('success', 0)
        remaining = data.get('remaining', 0)
        
        # ✅ STATE'İ GÜNCELLE - SAYAÇLAR İÇİN
        self.state.gonderilen = success
        self.state.toplam_hata = errors
        self.state.remaining_urls = remaining
        
        # İşlem durumunu güncelle
        if processed < total:
            self.state.current_processing_url = data.get('current_url', '')
            self.state.current_processing_stage = data.get('current_stage', 'İşleniyor')
            self.state.next_url = data.get('next_url', '')

    def on_scan_finished(self):
        # processing_info'yu ModernControlPanel'den gizle
        if hasattr(self, 'right_panel') and hasattr(self.right_panel, 'control_panel'):
            self.right_panel.control_panel.processing_info.setVisible(False)
        self.state.current_processing_stage = "Tamamlandı"
        self.state.current_processing_url = ""
        self.state.next_url = ""
        
        self.log_message("✅ Dosya taraması tamamlandı!", "success")

    def stop_scan(self):
        if hasattr(self, 'scan_thread') and self.scan_thread and self.scan_thread.isRunning():
            try:
                self.scan_thread.stop()  # Thread'in stop metodunu çağır
                self.scan_thread.wait(3000)  # 3 saniye bekle
                if self.scan_thread.isRunning():
                    self.scan_thread.terminate()  # Zorla sonlandır
                self.log_message("⏹️ Tarama durduruldu", "warning")
            except Exception as e:
                self.log_message(f"❌ Tarama durdurma hatası: {e}", "error")
        
        # processing_info kontrolü - ModernControlPanel'de olabilir
        if hasattr(self, 'right_panel') and hasattr(self.right_panel, 'control_panel'):
            if hasattr(self.right_panel.control_panel, 'processing_info'):
                self.right_panel.control_panel.processing_info.setVisible(False)
        
        self.state.current_processing_stage = "Durduruldu"

    def start_url_scan(self):
        urls_text = self.url_input.toPlainText().strip()
        if not urls_text:
            self.url_log_message("❌ Lütfen URL'leri girin!", "error")
            return
            
        urls = []
        for line in urls_text.split('\n'):
            url = line.strip()
            if url and ('http://' in url or 'https://' in url):
                urls.append(url)
        
        if not urls:
            self.url_log_message("❌ Geçerli URL bulunamadı!", "error")
            return
        
        # ✅ URL TARAMASI BAŞLAMADAN ÖNCE GRUP DURUMLARINI SIFIRLA
        self.reset_group_statuses()
        
        self.url_log_message(f"🚀 {len(urls)} URL taraması başlatıldı", "info")
        
        # Processor'ı parent ile bağla
        processor = M3UProcessor(self.state, self.bot_token, self.chat_ids, self)
        
        for i, url in enumerate(urls):
            try:
                # ✅ HER YENİ URL İÇİN GRUP DURUMLARINI SIFIRLA
                self.reset_group_statuses()
                
                self.state.current_processing_url = url
                self.state.current_processing_stage = "M3U bilgileri alınıyor"
                self.state.next_url = urls[i + 1] if i + 1 < len(urls) else ""
                
                result = processor.process_url(url)
                if result['status'] == 'success':
                    self.url_log_message(f"✅ GRUPLARA GÖNDERİLDİ: {url}", "success")
                    # ✅ SAYAÇ OTOMATİK OLARAK ARTACAK
                elif result['status'] == 'blocked':
                    self.url_log_message(f"🚫 ENGELLENDİ: {url}", "warning")
                    self.state.engellenen_msg += 1  # ✅ ENGELLENEN SAYACI
                else:
                    self.url_log_message(f"❌ HATA: {url}", "error")
                    self.state.toplam_hata += 1  # ✅ HATA SAYACI
                    
                time.sleep(0.5)
                
            except Exception as e:
                self.url_log_message(f"❌ İŞLEM HATASI: {str(e)}", "error")
                self.state.toplam_hata += 1
        
        self.state.current_processing_url = ""
        self.state.current_processing_stage = "Tamamlandı"
        self.state.next_url = ""

    def clear_urls(self):
        self.url_input.clear()

    def save_settings(self):
        try:
            QMessageBox.information(self, "Başarılı", "Ayarlar kaydedildi!")
            self.log_message("✅ Ayarlar kaydedildi", "success")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Ayarlar kaydedilemedi: {str(e)}")
            self.log_message(f"❌ Ayarlar kaydetme hatası: {str(e)}", "error")

    def reset_settings(self):
        reply = QMessageBox.question(
            self,
            "Onay",
            "Ayarları varsayılan değerlere sıfırlamak istediğinizden emin misiniz?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QDialog.Yes:
            self.bot_token_input.setText(BOT_TOKEN)
            self.api_id_input.setText(str(API_ID))
            self.api_hash_input.setText(API_HASH)
            self.session_name_input.setText(SESSION_NAME)
            self.github_repo_input.setText(GITHUB_REPO)
            self.github_token_input.setText(GITHUB_TOKEN)
            self.github_branch_input.setText(GITHUB_BRANCH)
            
            self.log_message("✅ Ayarlar varsayılana döndürüldü", "success")

    def update_status_display(self):
        self.right_panel.status_panel.update_display()
        self.right_panel.aday_panel.update_display()
        self.modern_processing_panel.update_display()
    def log_message(self, message, msg_type="info"):
        self._log_message(self.log_display, message, msg_type)

    def url_log_message(self, message, msg_type="info"):
        self._log_message(self.url_log, message, msg_type)

    def _log_message(self, log_widget, message, msg_type="info"):
        colors = {
            "info": "#3498db",
            "success": "#2ecc71", 
            "warning": "#f39c12",
            "error": "#e74c3c"
        }
        
        color = colors.get(msg_type, "#3498db")
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        html_message = f'<span style="color: {color}">[{timestamp}] {html.escape(message)}</span>'
        
        log_widget.append(html_message)
        log_widget.moveCursor(QTextCursor.End)

def load_json_safe(path, default=None):
    """JSON dosyasını güvenli şekilde yükle"""
    try:
        if not os.path.exists(path):
            return default or {}
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ JSON yükleme hatası {path}: {e}")
        return default or {}

def save_json_safe(path, data):
    """JSON dosyasını güvenli şekilde kaydet"""
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"❌ JSON kaydetme hatası {path}: {e}")
        return False

def atomic_write(path, content):
    """Atomik dosya yazma"""
    try:
        temp_path = path + '.tmp'
        with open(temp_path, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(content)
        if os.path.exists(path):
            os.remove(path)
        os.rename(temp_path, path)
        return True
    except Exception as e:
        print(f"❌ Atomik yazma hatası {path}: {e}")
        return False

# Global file lock
_FILE_LOCK = Lock()