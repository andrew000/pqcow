class SignatureVerificationError(Exception):
    def __init__(self, dilithium_public_key: bytes) -> None:
        super().__init__("Signature verification failed")
        self.dilithium_public_key: bytes = dilithium_public_key
