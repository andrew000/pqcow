import asyncio
import logging

from pqcow.client.async_client import AsyncClient

logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


async def create_client(host: str, port: int) -> AsyncClient:
    client = AsyncClient(host, port, None)
    await client.connect()
    return client


async def send_message(shit: list) -> None:
    await asyncio.gather(*shit)


async def close_client(client: AsyncClient) -> None:
    await client.close()


async def bench() -> None:
    connections_count = 10
    host = "192.168.0.111"
    port = 8080

    logger.info("Creating %d connections", connections_count)
    connections = await asyncio.gather(
        *[create_client(host, port) for _ in range(connections_count)],
    )
    logger.info("Connections created")

    await asyncio.sleep(1)

    logger.info("Sending messages")
    await asyncio.gather(
        *[
            send_message(
                [
                    client.send_message(
                        user_id=1,
                        text=f"[client:{client_id} msg:{i}] Hello World!",
                    )
                    for i in range(10_000)
                ],
            )
            for client_id, client in enumerate(connections)
        ],
    )
    logger.info("Messages sent")

    await asyncio.sleep(5)

    logger.info("Closing connections")
    await asyncio.gather(*[close_client(client) for client in connections])
    logger.info("Connections closed")

    await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(bench())
