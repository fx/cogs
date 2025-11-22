from .forwarder import Forwarder

async def setup(bot):
    await bot.add_cog(Forwarder(bot))