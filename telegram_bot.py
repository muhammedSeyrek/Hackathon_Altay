"""
Telegram Bot - Log Analiz Asistanı

Komutlar:
  /start       - Karşılama
  /yardim      - Komut listesi
  /analiz      - Mesaja eklenen logu analiz et (caption olarak veya text dosyası olarak)
  /grafik      - Son analiz edilen logun saatlik grafiğini gönder
  /soru <metin> - Gemini'ye hardening sorusu sor
  /temizle     - Sohbet geçmişini temizle

Direkt mesaj atınca da Gemini'ye soru olarak iletilir.
"""

import os
import io
import logging
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")  # GUI olmayan ortam için
import matplotlib.pyplot as plt

import google.generativeai as genai
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from dotenv import load_dotenv, find_dotenv

from log_parser import parse_log_text, summarize_attacks

# --- Ortam değişkenleri ---
load_dotenv(find_dotenv())
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")  # opsiyonel - proaktif uyarı için

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("logbot")

# Gemini'yi başlat
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Kullanıcı başına son analiz ve sohbet geçmişi
user_state: dict[int, dict] = defaultdict(dict)

SYSTEM_PROMPT_BASE = """Sen bir siber güvenlik uzmanısın. Log analizi yapmış bir kullanıcıya
Telegram üzerinden hardening önerileri veriyorsun.

Kurallar:
- Sadece TÜRKÇE cevap ver.
- Kısa, net, adım adım yaz. Telegram mesajına sığacak şekilde.
- Mümkünse kod blokları içinde komut örneği ver (iptables, ufw, fail2ban, sshd_config vb.).
- ASLA saldırı yöntemi öğretme; sadece SAVUNMA ve sertleştirme.
- Bilgi yetersizse hangi log/komut çıktısına ihtiyacın olduğunu sor.
"""


def build_system_prompt(user_id: int) -> str:
    """Kullanıcının son analiz özetini system prompt'a ekler."""
    state = user_state.get(user_id, {})
    summary = state.get("summary")
    if not summary:
        return SYSTEM_PROMPT_BASE

    ctx = f"""
--- Kullanıcının son log analizi ---
Toplam olay: {summary['total']}
Şüpheli/saldırı: {summary['attack_count']}
En yoğun saat: {summary['peak_hour']}:00 ({summary['peak_hour_count']} olay)
Saldırı türleri: {summary['top_categories']}
En aktif IP'ler: {summary['top_ips']}
"""
    return SYSTEM_PROMPT_BASE + ctx


async def ask_gemini(user_id: int, question: str) -> str:
    """Gemini'ye soru sorar, kullanıcı bazlı geçmiş tutar."""
    if not GEMINI_API_KEY:
        return "❌ GEMINI_API_KEY tanımlı değil."

    try:
        model = genai.GenerativeModel(
            "gemini-1.5-flash",
            system_instruction=build_system_prompt(user_id),
        )

        history = user_state[user_id].get("chat_history", [])
        chat = model.start_chat(history=history)
        response = chat.send_message(question)

        # Geçmişi güncelle
        history.append({"role": "user", "parts": [question]})
        history.append({"role": "model", "parts": [response.text]})
        user_state[user_id]["chat_history"] = history[-20:]  # son 20 mesaj

        return response.text
    except Exception as e:
        log.exception("Gemini hatası")
        return f"❌ Gemini hatası: {e}"


# --- Handler'lar ---

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🛡️ *Log Saldırı Analiz Botu*\n\n"
        "Loglarını analiz edip hardening önerisi verebilirim.\n\n"
        "Komutlar için /yardim yaz."
    )
    await update.message.reply_markdown(msg)


async def cmd_yardim(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "*Komutlar:*\n"
        "/analiz - Bir mesaja log yapıştırıp birlikte gönder veya `.log/.txt` dosyası ekleyip caption olarak `/analiz` yaz\n"
        "/grafik - Son analizin saatlik grafiğini gönderir\n"
        "/soru <metin> - Gemini'ye hardening sorusu sor\n"
        "/temizle - Sohbet geçmişini sıfırla\n\n"
        "Komut olmadan yazdığın her şey doğrudan Gemini'ye gider."
    )
    await update.message.reply_markdown(msg)


async def cmd_analiz(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    log_text = ""

    # 1) Dosya eki var mı?
    if update.message.document:
        doc = update.message.document
        if doc.file_size and doc.file_size > 5 * 1024 * 1024:
            await update.message.reply_text("❌ Dosya çok büyük (>5MB). Daha küçük bir kesit gönder.")
            return
        try:
            file = await doc.get_file()
            data = await file.download_as_bytearray()
            log_text = data.decode("utf-8", errors="ignore")
        except Exception as e:
            await update.message.reply_text(f"❌ Dosya alınamadı: {e}")
            return

    # 2) Komut argümanı veya cevaplanan mesaj
    elif context.args:
        log_text = " ".join(context.args)
    elif update.message.reply_to_message and update.message.reply_to_message.text:
        log_text = update.message.reply_to_message.text

    if not log_text.strip():
        await update.message.reply_text(
            "📥 Logu analiz etmem için:\n"
            "• `.log` veya `.txt` dosyası gönder, caption olarak `/analiz` yaz\n"
            "• Ya da log içeren bir mesajı cevaplayıp `/analiz` yaz\n"
            "• Ya da `/analiz <log satırları>` şeklinde gönder"
        )
        return

    await update.message.reply_text("🔍 Log analiz ediliyor...")

    df = parse_log_text(log_text)
    if df.empty:
        await update.message.reply_text("❌ Hiçbir satır parse edilemedi.")
        return

    summary = summarize_attacks(df)
    user_state[user_id]["summary"] = summary
    user_state[user_id]["log_text"] = log_text

    # Özet metni
    cats = "\n".join(f"  • {k}: {v}" for k, v in summary["top_categories"].items()) or "  (yok)"
    ips = "\n".join(f"  • {k}: {v}" for k, v in list(summary["top_ips"].items())[:5]) or "  (yok)"

    reply = (
        f"📊 *Analiz Sonucu*\n\n"
        f"Toplam satır: `{summary['total']}`\n"
        f"Şüpheli/saldırı: `{summary['attack_count']}`\n"
        f"En yoğun saat: `{summary['peak_hour']}:00` ({summary['peak_hour_count']} olay)\n\n"
        f"*Saldırı türleri:*\n{cats}\n\n"
        f"*En aktif IP'ler:*\n{ips}\n\n"
        f"Grafik için: /grafik\n"
        f"Hardening önerisi için: /soru <sorun>"
    )
    await update.message.reply_markdown(reply)


async def cmd_grafik(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    summary = user_state.get(user_id, {}).get("summary")

    if not summary:
        await update.message.reply_text("Önce /analiz ile bir log analiz et.")
        return

    hourly = summary["hourly"]

    fig, ax = plt.subplots(figsize=(10, 4))
    bars = ax.bar(hourly.index, hourly.values, color="#d62728", edgecolor="black")
    ax.set_xlabel("Saat (00–23)")
    ax.set_ylabel("Saldırı sayısı")
    ax.set_title("Saatlik Saldırı Dağılımı")
    ax.set_xticks(range(24))
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    if hourly.max() > 0:
        peak = int(hourly.idxmax())
        bars[peak].set_color("#8B0000")

    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", dpi=110)
    plt.close(fig)
    buf.seek(0)

    await update.message.reply_photo(
        photo=buf,
        caption=f"⏰ En yoğun saat: {summary['peak_hour']}:00 ({summary['peak_hour_count']} olay)"
    )


async def cmd_soru(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("Kullanım: `/soru SSH brute force saldırısı için ne yapmalıyım?`",
                                        parse_mode="Markdown")
        return
    question = " ".join(context.args)
    await update.message.chat.send_action("typing")
    answer = await ask_gemini(user_id, question)
    await update.message.reply_text(answer)


async def cmd_temizle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_state[user_id]["chat_history"] = []
    await update.message.reply_text("🗑️ Sohbet geçmişi temizlendi.")


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Komut olmayan düz mesajları Gemini'ye yönlendir."""
    user_id = update.effective_user.id
    text = update.message.text or ""
    if not text.strip():
        return
    await update.message.chat.send_action("typing")
    answer = await ask_gemini(user_id, text)
    await update.message.reply_text(answer)


def main():
    if not TELEGRAM_TOKEN:
        raise SystemExit("TELEGRAM_BOT_TOKEN tanımlı değil. .env dosyasını kontrol et.")
    if not GEMINI_API_KEY:
        log.warning("GEMINI_API_KEY tanımlı değil — chatbot çalışmayacak.")

    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("yardim", cmd_yardim))
    app.add_handler(CommandHandler("help", cmd_yardim))
    app.add_handler(CommandHandler("analiz", cmd_analiz))
    app.add_handler(CommandHandler("grafik", cmd_grafik))
    app.add_handler(CommandHandler("soru", cmd_soru))
    app.add_handler(CommandHandler("temizle", cmd_temizle))

    # Caption'da /analiz olan dosyaları yakala
    app.add_handler(MessageHandler(filters.Document.ALL & filters.CaptionRegex(r"^/analiz"), cmd_analiz))

    # Düz metin mesajları
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    log.info("Bot çalışıyor...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()