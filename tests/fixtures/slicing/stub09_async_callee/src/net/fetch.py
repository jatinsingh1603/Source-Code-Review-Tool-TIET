import aiohttp


async def fetch(session, url, timeout=30):
    async with session.get(url) as response:
        return await response.text()
