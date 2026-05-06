"""
Log Saldırı Analiz Aracı
- Streamlit arayüzü
- Log dosyası yükle veya copy-paste
- Saatlik saldırı grafiği
- Gemini destekli chatbot (hardening önerileri)
"""

import os
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from google import genai
from dotenv import load_dotenv, find_dotenv

from log_parser import parse_log_text, summarize_attacks

# --- Ortam değişkenleri ---
load_dotenv(find_dotenv())
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# --- Sayfa ayarları ---
st.set_page_config(
    page_title="Log Saldırı Analizi",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Log Saldırı Analiz Aracı")
st.caption("Log dosyanı yükle veya yapıştır → saatlik saldırı grafiğini gör → Gemini'ye hardening önerisi sor.")

# --- Gemini'yi hazırla ---
gemini_client = None
if GEMINI_API_KEY:
    try:
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception as e:
        st.warning(f"Gemini başlatılamadı: {e}")
else:
    st.error("❌ GEMINI_API_KEY bulunamadı! .env dosyasında ayarlayın.")

# --- Session state ---
if "log_text" not in st.session_state:
    st.session_state.log_text = ""
if "df" not in st.session_state:
    st.session_state.df = None
if "summary" not in st.session_state:
    st.session_state.summary = None
if "messages" not in st.session_state:
    st.session_state.messages = []

# --- Log Girişi ---
st.subheader("1. Log Girişi")

col1, col2 = st.columns(2)

with col1:
    uploaded = st.file_uploader("Log dosyası yükle (.log, .txt)", type=["log", "txt"])
    if uploaded is not None:
        try:
            st.session_state.log_text = uploaded.read().decode("utf-8", errors="ignore")
            st.success(f"Yüklendi: {uploaded.name} ({len(st.session_state.log_text)} karakter)")
        except Exception as e:
            st.error(f"Dosya okunamadı: {e}")

with col2:
    pasted = st.text_area(
        "...veya log içeriğini buraya yapıştır",
        value="",
        height=200,
        placeholder="Log satırlarını buraya yapıştır..."
    )
    if st.button("Yapıştırılan logu kullan"):
        if pasted.strip():
            st.session_state.log_text = pasted
            st.success(f"Log alındı ({len(pasted)} karakter)")
        else:
            st.warning("Boş içerik")

# --- Analiz ---
st.subheader("2. Analiz")

if st.button("🔍 Logu Analiz Et", type="primary", disabled=not st.session_state.log_text):
    with st.spinner("Log parse ediliyor..."):
        df = parse_log_text(st.session_state.log_text)
        st.session_state.df = df
        st.session_state.summary = summarize_attacks(df)

if st.session_state.df is not None:
    df = st.session_state.df
    summary = st.session_state.summary

    if df.empty:
        st.error("Hiç log satırı parse edilemedi. Format desteklenmiyor olabilir.")
    else:
        st.info(f"Toplam **{len(df)}** satır parse edildi · "
                f"Şüpheli/saldırı: **{summary['attack_count']}**")

        # --- Grafik ---
        st.subheader("3. Saatlik Saldırı Grafiği")
        hourly = summary["hourly"]

        fig, ax = plt.subplots(figsize=(11, 4))
        bars = ax.bar(hourly.index, hourly.values, color="#d62728", edgecolor="black")
        ax.set_xlabel("Saat (00–23)")
        ax.set_ylabel("Saldırı / Şüpheli olay sayısı")
        ax.set_title("Saatlik Saldırı Dağılımı")
        ax.set_xticks(range(24))
        ax.grid(axis="y", linestyle="--", alpha=0.5)

        # En yoğun saati vurgula
        if hourly.max() > 0:
            peak_hour = int(hourly.idxmax())
            bars[peak_hour].set_color("#8B0000")

        st.pyplot(fig)

        # En yoğun saatler tablosu
        with st.expander("📊 Detaylı saatlik dağılım"):
            st.dataframe(
                pd.DataFrame({"Saat": hourly.index, "Olay Sayısı": hourly.values}),
                use_container_width=True,
                hide_index=True,
            )

        # En çok görülen saldırı türleri
        if summary["top_categories"]:
            with st.expander("🎯 Saldırı türü dağılımı"):
                cat_df = pd.DataFrame(
                    list(summary["top_categories"].items()),
                    columns=["Kategori", "Sayı"],
                )
                st.dataframe(cat_df, use_container_width=True, hide_index=True)

        # En çok saldıran IP'ler
        if summary["top_ips"]:
            with st.expander("🌐 En çok saldıran IP'ler"):
                ip_df = pd.DataFrame(
                    list(summary["top_ips"].items()),
                    columns=["IP", "Olay Sayısı"],
                )
                st.dataframe(ip_df, use_container_width=True, hide_index=True)

# --- Chatbot ---
st.subheader("4. 💬 Hardening Asistanı (Gemini)")

if gemini_client is None:
    st.info("Chatbotu kullanmak için GEMINI_API_KEY gerekli.")
else:
    # Önceki mesajları göster
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    user_input = st.chat_input("Hardening önerisi iste, soru sor... (örn: 'Bu sonuçlara göre adım adım ne yapmalıyım?')")

    if user_input:
        st.session_state.messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        # Bağlam oluştur (analiz varsa)
        context = ""
        if st.session_state.summary:
            s = st.session_state.summary
            context = f"""
Kullanıcının log analiz sonuçları:
- Toplam olay: {s['total']}
- Şüpheli/saldırı olayı: {s['attack_count']}
- En yoğun saat: {s['peak_hour']}:00 ({s['peak_hour_count']} olay)
- Saldırı türleri: {s['top_categories']}
- En aktif IP'ler: {s['top_ips']}
"""

        system_prompt = f"""Sen bir siber güvenlik uzmanısın. Kullanıcı log analizi yaptı ve sana sorular soruyor.
Sadece Türkçe yanıt ver. Kısa, pratik, adım adım hardening önerileri ver.
Komut örnekleri (iptables, fail2ban, ufw, sshd_config vb.) ekle.
Asla saldırı yöntemleri öğretme; sadece SAVUNMA ve sertleştirme öner.

{context}
"""

        with st.chat_message("assistant"):
            with st.spinner("Düşünüyor..."):
                try:
                    # Konuşma geçmişini Gemini formatına çevir
                    contents = []
                    for m in st.session_state.messages:
                        role = "user" if m["role"] == "user" else "model"
                        contents.append({
                            "role": role,
                            "parts": [{"text": m["content"]}],
                        })

                    response = gemini_client.models.generate_content(
                        model="gemini-2.5-flash",
                        contents=contents,
                        config={"system_instruction": system_prompt},
                    )
                    answer = response.text
                except Exception as e:
                    answer = f"Hata: {e}"

                st.markdown(answer)
                st.session_state.messages.append({"role": "assistant", "content": answer})

    if st.button("🗑️ Sohbeti temizle"):
        st.session_state.messages = []
        st.rerun()

st.divider()
st.caption("💡 Telegram botunu çalıştırmak için: `python telegram_bot.py`")