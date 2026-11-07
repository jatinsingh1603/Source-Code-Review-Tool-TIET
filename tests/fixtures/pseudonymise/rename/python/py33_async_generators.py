async def stream_rows(session_handle):
    async for chunk_row in session_handle.fetch_all():
        yield chunk_row


async def gather(session_handle):
    return [row async for row in stream_rows(session_handle)]
