"""
CLI Runner: Log dosyasını analiz eder, grafiği Telegram grubuna/kanalına gönderir.
GitHub Actions zamanlanmış görevler için tasarlandı.

Kullanım:
    python run_analysis.py <log_dosyasi>
    python run_analysis.py logs/access.log

Ortam değişkenleri (workflow secret'larından gelir):
    TELEGRAM_BOT_TOKEN
    TELEGRAM_CHAT_ID
    GEMINI_API_KEY (opsiyonel - hardening önerisi de gönderilir)
"""

import os
import sys
import io
import asyncio

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from telegram import Bot
from telegram.constants import ParseMode

from log_parser import parse_log_text, summarize_attacks


def make_chart(summary) -> bytes:
    """Saatlik saldırı grafiğini PNG bytes olarak döner."""
    hourly = summary["hourly"]
    fig, ax = plt.subplots(figsize=(10, 4))
    bars = ax.bar(hourly.index, hourly.values, color="#d62728", edgecolor="black")
    ax.set_xlabel("Saat (00–23)")
    ax.set_ylabel("Saldırı sayısı")
    ax.set_title("Saatlik Saldırı Dağılımı")
    ax.set_xticks(range(24))
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    if hourly.max() > 0:
        bars[int(hourly.idxmax())].set_color("#8B0000")
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", dpi=110)
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


def make_summary_text(summary, source_name: str) -> str:
    cats = "\n".join(f"  • {k}: {v}" for k, v in summary["top_categories"].items()) or "  (yok)"
    ips = "\n".join(f"  • `{k}`: {v}" for k, v in list(summary["top_ips"].items())[:5]) or "  (yok)"
    return (
        f"🛡️ *Otomatik Log Analizi*\n"
        f"Kaynak: `{source_name}`\n\n"
        f"Toplam satır: `{summary['total']}`\n"
        f"Şüpheli/saldırı: `{summary['attack_count']}`\n"
        f"En yoğun saat: `{summary['peak_hour']}:00` "
        f"({summary['peak_hour_count']} olay)\n\n"
        f"*Saldırı türleri:*\n{cats}\n\n"
        f"*En aktif IP'ler:*\n{ips}"
    )


def gemini_recommendation(summary) -> str | None:
    """Gemini'den kısa hardening önerisi al (opsiyonel)."""
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return None
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        prompt = f"""Aşağıdaki log analiz sonuçlarına göre en kritik 3 hardening önerisini Türkçe, kısa ve komut örnekli ver.
Maksimum 1500 karakter. Sadece savunma; saldırı tekniği yazma.

Toplam olay: {summary['total']}
Saldırı: {summary['attack_count']}
En yoğun saat: {summary['peak_hour']}:00 ({summary['peak_hour_count']} olay)
Saldırı türleri: {summary['top_categories']}
En aktif IP'ler: {summary['top_ips']}
"""
        model = genai.GenerativeModel("gemini-1.5-flash")
        return model.generate_content(prompt).text
    except Exception as e:
        print(f"[uyarı] Gemini önerisi alınamadı: {e}", file=sys.stderr)
        return None


async def send_to_telegram(token: str, chat_id: str,
                           caption: str, chart_bytes: bytes,
                           extra_text: str | None = None):
    bot = Bot(token=token)
    await bot.send_photo(
        chat_id=chat_id,
        photo=chart_bytes,
        caption=caption,
        parse_mode=ParseMode.MARKDOWN,
    )
    if extra_text:
        # Telegram mesaj limiti ~4096
        for chunk in [extra_text[i:i+3800] for i in range(0, len(extra_text), 3800)]:
            await bot.send_message(
                chat_id=chat_id,
                text=f"💡 *Hardening önerisi*\n\n{chunk}",
                parse_mode=ParseMode.MARKDOWN,
            )


def main():
    if len(sys.argv) < 2:
        print("Kullanım: python run_analysis.py <log_dosyasi>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"❌ Dosya bulunamadı: {path}")
        sys.exit(1)

    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        print("❌ TELEGRAM_BOT_TOKEN ve TELEGRAM_CHAT_ID gerekli.")
        sys.exit(1)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    df = parse_log_text(text)
    if df.empty:
        print("❌ Hiçbir satır parse edilemedi.")
        sys.exit(1)

    summary = summarize_attacks(df)
    print(f"✅ {summary['total']} satır, {summary['attack_count']} saldırı tespit edildi.")
    print(f"Peak: {summary['peak_hour']}:00 ({summary['peak_hour_count']} olay)")

    chart = make_chart(summary)
    caption = make_summary_text(summary, os.path.basename(path))
    advice = gemini_recommendation(summary)

    asyncio.run(send_to_telegram(token, chat_id, caption, chart, advice))
    print("📤 Telegram'a gönderildi.")


if __name__ == "__main__":
    main()