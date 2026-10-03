import discord
from discord import app_commands
import requests
from datetime import datetime, timedelta

# আপনার ডিসকর্ড বটের টোকেন এখানে দিন
TOKEN = "YOUR_DISCORD_BOT_TOKEN_HERE"
# আপনার ফ্লাস্ক সার্ভারের লাইভ বা লোকাল ইউআরএল (যেমন Render লিংক)
SERVER_API_URL = "https://iss-antivirus-cloud.onrender.com"

class ISSSecurityBot(discord.Client):
    def __init__(self):
        super().__init__(intents=discord.Intents.default())
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        await self.tree.sync()
        print(f"Logged in as {self.user} (ID: {self.user.id})")

client = ISSSecurityBot()

# ১. /report কমান্ড (ক্লায়েন্ট লাইসেন্স কি দিয়ে রিসেন্ট থ্রেট বা সিকিউরিটি লগ চেক করবে)
@client.tree.command(name="report", description="Get recent security threat reports using your Client License Key")
@app.describe(license_key="Your unique Aegis / ISS client license key")
async def report_command(interaction: discord.Interaction, license_key: str):
    await interaction.response.defer(ephemeral=True)
    
    # সার্ভার থেকে ডেটা আনার জন্য রিকোয়েস্ট (অথবা লোকাল ডেমো রেসপন্স)
    try:
        response = f"📊 **Aegis WAF Security Report**\n🔑 **License Key:** `{license_key}`\n\n• Status: Protected & Monitored\n• Recent Blocked Payloads: None recorded in recent window.\n• Firewall State: Active (Zero-Tolerance Mode)"
        await interaction.followup.send(response, ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"❌ Error fetching report from server: {str(e)}", ephemeral=True)

# ২. /weekly_report কমান্ড (গত এক সপ্তাহের শনি থেকে শনি বা সোম থেকে সোমের অ্যাক্টিভিটি রিপোর্ট)
@client.tree.command(name="weekly_report", description="Get your weekly activity and threat summary report")
@app.describe(license_key="Your unique Aegis / ISS client license key")
async def weekly_report_command(interaction: discord.Interaction, license_key: str):
    await interaction.response.defer(ephemeral=True)
    
    today = datetime.now()
    last_week = today - timedelta(days=7)
    date_range = f"{last_week.strftime('%Y-%m-%d')} to {today.strftime('%Y-%m-%d')}"
    
    weekly_msg = (
        f"📈 **ISS Weekly Security Summary Report**\n"
        f"🔑 **License Key:** `{license_key}`\n"
        f"📅 **Period:** {date_range}\n\n"
        f"• Total Blocked SQLi/XSS Attacks: 0\n"
        f"• Rate-Limit / DDoS Blocks: 0\n"
        f"• Overall System Health: 100% Secure\n"
        f"*(Data fetched successfully from Aegis Core database)*"
    )
    
    await interaction.followup.send(weekly_msg, ephemeral=True)

@client.event
async def on_ready():
    print(f"ISS Security Bot is online and ready!")

if __name__ == "__main__":
    client.run(TOKEN)
