from .example import ExampleCog

async def setup(bot):
    await bot.add_cog(ExampleCog(bot))