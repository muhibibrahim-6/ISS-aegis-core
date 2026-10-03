import discord
from discord import app_commands
import requests

TOKEN = "YOUR_DISCORD_BOT_TOKEN_HERE"
# আপনার ফ্লাস্ক সার্ভারের লাইভ বা লোকাল ইউআরএল
SERVER_API_URL = "https://iss-antivirus-cloud.onrender.com"

class ISSSecurityBot(discord.Client):
    def __init__(self):
        super().__init__(intents=discord.Intents.default())
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        await self.tree.sync()
        print(f"Logged in as {self.user}")

client = ISSSecurityBot()

@client.tree.command(name="report", description="Get recent security threat reports using your Client License Key")
@app.describe(license_key="Your unique Aegis client license key")
async def report_command(interaction: discord.Interaction, license_key: str):
    await interaction.response.defer(ephemeral=True)
    try:
        res = requests.get(f"{SERVER_API_URL}/api/report?license_key={license_key}", timeout=5)
        data = res.json()
        if res.status_code != 200:
            await interaction.followup.send(f"❌ Error: {data.get('error', 'Invalid License Key')}", ephemeral=True)
            return
        
        threats = data.get('recent_threats', [])
        if not threats:
            msg = f"📊 **Aegis WAF Security Report**\n🔑 **License Key:** `{license_key}`\n\n✅ No recent threats recorded. Your server is fully protected!"
        else:
            msg = f"📊 **Aegis WAF Recent Threat Report**\n🔑 **License Key:** `{license_key}`\n\n"
            for t in threats:
                msg += f"• **Threat:** {t['threat_type']}\n  **IP:** {t['attacker_ip']}\n  **Path:** {t['path']}\n  **Time:** {t['timestamp']}\n\n"
        
        await interaction.followup.send(msg, ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"❌ Server connection failed: {str(e)}", ephemeral=True)

@client.tree.command(name="weekly_report", description="Get your weekly activity and threat summary report")
@app.describe(license_key="Your unique Aegis client license key")
async def weekly_report_command(interaction: discord.Interaction, license_key: str):
    await interaction.response.defer(ephemeral=True)
    try:
        res = requests.get(f"{SERVER_API_URL}/api/weekly_report?license_key={license_key}", timeout=5)
        data = res.json()
        if res.status_code != 200:
            await interaction.followup.send(f"❌ Error: {data.get('error', 'Invalid License Key')}", ephemeral=True)
            return
        
        total = data.get('total_threats_this_week', 0)
        msg = (
            f"📈 **ISS Weekly Security Summary Report**\n"
            f"🔑 **License Key:** `{license_key}`\n"
            f"🏢 **Client Name:** {data.get('client_name')}\n\n"
            f"• Total Blocked Attacks This Week: **{total}**\n"
            f"• System Health: **100% Secure & Monitored**"
        )
        await interaction.followup.send(msg, ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"❌ Server connection failed: {str(e)}", ephemeral=True)

@client.event
async def on_ready():
    print(f"Bot is ready and connected to Aegis API!")

if __name__ == "__main__":
    client.run(TOKEN)
