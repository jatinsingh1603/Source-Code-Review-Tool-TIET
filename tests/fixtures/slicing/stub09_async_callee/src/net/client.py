from net.fetch import fetch


async def pull(session, url):
    body = await fetch(session, url)
    return body
