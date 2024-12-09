class SignatureVerificationError(Exception):
    def __init__(self, dilithium_public_key: bytes) -> None:
        super().__init__("Signature verification failed")
        self.dilithium_public_key: bytes = dilithium_public_key


class ChatNotFoundError(Exception):
    def __init__(self, user_id: int) -> None:
        super().__init__(f"Chat with user_id {user_id} not found")
        self.user_id: int = user_id
