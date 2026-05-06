"""
CLI Runner: Log dosyasını analiz eder, grafiği Telegram grubuna/kanalına gönderir.
GitHub Actions zamanlanmış görevler için tasarlandı.

Kullanım:
    python run_analysis.py <log_dosyasi>

Ortam değişkenleri:
    TELEGRAM_BOT_TOKEN
    TELEGRAM_CHAT_ID
    GEMINI_API_KEY (opsiyonel)
"""

import os
import sys
import io
import html
import asyncio

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from telegram import Bot
from telegram.constants import ParseMode

from log_parser import parse_log_text, summarize_attacks


def make_chart(summary) -> bytes:
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


def make_summary_html(summary, source_name: str) -> str:
    """Telegram HTML parse mode için özet üretir. IP nokta-virgül vs. sorun çıkarmaz."""
    cats = "\n".join(
        f"  • {html.escape(str(k))}: {v}" for k, v in summary["top_categories"].items()
    ) or "  (yok)"
    ips = "\n".join(
        f"  • <code>{html.escape(str(k))}</code>: {v}"
        for k, v in list(summary["top_ips"].items())[:5]
    ) or "  (yok)"
    return (
        f"🛡️ <b>Otomatik Log Analizi</b>\n"
        f"Kaynak: <code>{html.escape(source_name)}</code>\n\n"
        f"Toplam satır: <code>{summary['total']}</code>\n"
        f"Şüpheli/saldırı: <code>{summary['attack_count']}</code>\n"
        f"En yoğun saat: <code>{summary['peak_hour']}:00</code> "
        f"({summary['peak_hour_count']} olay)\n\n"
        f"<b>Saldırı türleri:</b>\n{cats}\n\n"
        f"<b>En aktif IP'ler:</b>\n{ips}"
    )


def gemini_recommendation(summary) -> str | None:
    """Gemini'den kısa hardening önerisi al (yeni google-genai SDK ile)."""
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return None
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        prompt = f"""Aşağıdaki log analiz sonuçlarına göre en kritik 3 hardening önerisini Türkçe, kısa ve komut örnekli ver.
Maksimum 1500 karakter. Sadece savunma; saldırı tekniği yazma.
Markdown veya HTML formatlama KULLANMA, düz metin yaz.

Toplam olay: {summary['total']}
Saldırı: {summary['attack_count']}
En yoğun saat: {summary['peak_hour']}:00 ({summary['peak_hour_count']} olay)
Saldırı türleri: {summary['top_categories']}
En aktif IP'ler: {summary['top_ips']}
"""
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        return response.text
    except Exception as e:
        print(f"[uyarı] Gemini önerisi alınamadı: {e}", file=sys.stderr)
        return None


async def send_to_telegram(token: str, chat_id: str,
                           caption_html: str, chart_bytes: bytes,
                           extra_text: str | None = None):
    bot = Bot(token=token)
    await bot.send_photo(
        chat_id=chat_id,
        photo=chart_bytes,
        caption=caption_html,
        parse_mode=ParseMode.HTML,
    )
    if extra_text:
        # Düz metin olarak gönder; HTML escape uygula. 4096 karakter limiti var.
        safe = html.escape(extra_text)
        for chunk in [safe[i:i+3800] for i in range(0, len(safe), 3800)]:
            await bot.send_message(
                chat_id=chat_id,
                text=f"💡 <b>Hardening önerisi</b>\n\n{chunk}",
                parse_mode=ParseMode.HTML,
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
    caption = make_summary_html(summary, os.path.basename(path))
    advice = gemini_recommendation(summary)

    asyncio.run(send_to_telegram(token, chat_id, caption, chart, advice))
    print("📤 Telegram'a gönderildi.")


if __name__ == "__main__":
    main()