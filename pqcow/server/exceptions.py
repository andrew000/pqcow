class SignatureVerificationError(Exception):
    def __init__(self, dilithium_public_key: bytes) -> None:
        super().__init__("Signature verification failed")
        self.dilithium_public_key: bytes = dilithium_public_key


class ChatNotFoundError(Exception):
    def __init__(self, chat_id: int) -> None:
        super().__init__(f"Chat with id {chat_id} not found")
        self.chat_id: int = chat_id
