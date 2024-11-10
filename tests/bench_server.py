import asyncio

from pqcow_client.src.__main__ import start_client


async def create_connection(host: str, port: int) -> None:
    return await start_client(host, port)


async def send_message(writer: asyncio.StreamWriter, message: str) -> None:
    writer.write(message.encode())
    await writer.drain()


async def close_connection(writer: asyncio.StreamWriter) -> None:
    writer.close()
    await writer.wait_closed()


async def test() -> None:
    connections_count = 10000
    host = "127.0.0.1"
    port = 8080

    connections = [create_connection(host, port) for _ in range(connections_count)]
    connections = await asyncio.gather(*connections)

    await asyncio.sleep(100)

    # await asyncio.gather(*[send_message(writer, "Hello, world!") for _, writer in connections])
    #
    # await asyncio.sleep(1)
    #
    # await asyncio.gather(*[close_connection(writer) for _, writer in connections])


if __name__ == "__main__":
    asyncio.run(test())
