from redbot.core import commands

class ExampleCog(commands.Cog):
    """Example custom cog for Red-DiscordBot"""
    
    def __init__(self, bot):
        self.bot = bot
    
    @commands.command()
    async def hello(self, ctx):
        """Say hello!"""
        await ctx.send(f"Hello, {ctx.author.mention}!")
    
    @commands.command()
    async def latency(self, ctx):
        """Check bot latency"""
        latency = round(self.bot.latency * 1000)
        await ctx.send(f"Pong! {latency}ms")