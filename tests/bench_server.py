import asyncio

from pqcow_client.src.client import Client


async def create_client(host: str, port: int) -> Client:
    client = Client(host, port, None)
    await client.connect()
    return client


async def send_message(client: Client, message: str) -> None:
    for i in range(1_000):
        await client.send_message(chat_id=1, text=f"[{i}] {message}")


async def bench() -> None:
    connections_count = 100
    host = "127.0.0.1"
    port = 8080

    connections = await asyncio.gather(*[create_client(host, port) for _ in range(connections_count)])

    await asyncio.gather(*[send_message(client, "Hello, world!") for client in connections])


if __name__ == "__main__":
    asyncio.run(bench())
