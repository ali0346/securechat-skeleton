# """Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

# import os
# from hashlib import sha256
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import dh

# # Pre-defined DH parameters (Group 14, RFC 3526)
# # These are strong, well-known parameters.
# # We represent P as bytes and convert to an int, which is more robust.
# DH_P_BYTES = (
#     b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2\x21\x68\xC2\x34'
#     b'\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1\x29\x02\x4E\x08\x8A\x67\xCC\x74'
#     b'\x02\x0B\xBE\xA6\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD'
#     b'\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D\xF2\x5F\x14\x37'
#     b'\x4F\xE1\x35\x6D\x6D\x51\xC2\x45\xE4\x85\xB5\x76\x62\x5E\x7E\xC6'
#     b'\xF4\x4C\x42\xE9\xA6\x37\xED\x6B\x0B\xFF\x5C\xB6\xF4\x06\xB7\xED'
#     b'\xEE\x38\x6B\xFB\x5A\x89\x9F\xA5\xAE\x9F\x24\x11\x7C\x4B\x1F\xE6'
#     b'\x49\x28\x66\x51\xEC\xE4\x5B\x3D\xC2\x00\x7C\xB8\xA1\x63\xBF\x05'
#     b'\x98\xDA\x48\x36\x1C\x55\xD3\x9A\x69\x16\x3F\xA8\xFD\x24\xCF\x5F'
#     b'\x83\x65\x5D\x23\xDC\xA3\xAD\x96\x1C\x62\xF3\x56\x20\x85\x52\xBB'
#     b'\x9E\xD5\x29\x07\x70\x96\x96\x6D\x67\x0C\x35\x4E\x4A\xBC\x98\x04'
#     b'\xF1\x74\x6C\x08\xCA\x18\x21\x7C\x32\x90\x5E\x46\x2E\x36\xCE\x3B'
#     b'\xE3\x9E\x77\x2C\x18\x0E\x86\x03\x9B\x27\x83\xA2\xEC\x07\xA2\x8F'
#     b'\xB5\xC5\x5D\xF0\x6F\x4C\x52\xC9\xDE\x2B\xCB\xF6\x95\x58\x17\x18'
#     b'\x39\x95\x49\x7C\x45\xAE\x48\x5F\xD5\xB3\xE9\x6C\x3A\x67\x15\xDE'
#     b'\x43\x15\xD0\x07\x81\x63\x8B\x8E\x25\xF2\xF1\xCB\x5D\xF1\xC0\x11'
#     b'\x4B\xFB\x11\x8B\xF1\x58\x1C\x06\x65\x99\x48\xC8\x9E\x4B\x08\xF5'
#     b'\x83\x4F\x64\xFB\xF3\xDE\x36\x42\x0E\x8C\x82\x93\xA3\x51\x85\x9C'
#     b'\x81\x4B\x4F\x81\x13\x62\xE8\x9F\x73\x79\xCE\x8F\xDE\xF1\x21\x3A'
#     b'\x50\x00\x45\x61\x32\xAE\x1B\x7F\x53\x5E\xE7\x48\x83\xFC\x80\x2B'
#     b'\x86\xCF\xA6\x86\x27\x9C\x49\x8E\xEC\x1F\xAD\x3A\x8F\x27\x1A\xF3'
#     b'\x7B\x4B\x73\x71\xD7\x96\x4B\x7E\x6C\x8F\x9D\x3E\x70\x1C\x4D\x48'
#     b'\x6B\x0F\x84\x3B\x21\xDF\x14\x1B\x2A\xE0\x9A\xB6\x31\x3C\x3B\x98'
#     b'\xF5\x2D\x80\x32\x0A\x31\x7F\x7C\x47\x95\x3F\x89\x68\x8E\x95\x3A'
#     b'\xB5\x93\x8A\xF1\x2B\x73\x27\xBA\x77\x89\xAB\x13\x49\x7F\x5F\xAF'
#     b'\x6A\x27\x69\x0E\x17\x1D\x4C\x41\x1B\xF1\x1A\x04\x97\x64\x7D\x22'
#     b'\xF9\x04\x13\x1B\xDE\xFB\x8B\xF9\x7D\x54\x7A\xCD\x1B\xF7\x8B\x8A'
#     b'\xF1\xAE\x0A\x1C\x9E\x4F\x62\x7E\x6D\x61\x87\x0D\x49\x53\x1C\x01'
#     b'\x51\x40\x69\x40\x17\x92\x8F\x7C\x09\x20\x23\x74\x9B\x7E\x8F\x8C'
#     b'\x8B\x5F\x2A\x0A\x08\x9D\x7E\x3A\x48\xCC\x7F\x2C\x1E\x6F\x33\x3E'
#     b'\x83\x93\xBC\xF8\x24\x94\x28\x00\x1B\x6F\x3E\x4C\x4F\x0E\x0E\x1C'
#     b'\x5F\x73\x21\x80\x9F\x02\x47\x9B\x82\xFD\x84\x32\xE2\xAA\xFF\xFF'
#     b'\xFF\xFF\xFF\xFF\xFF\xFF'
# )

# DH_P = int.from_bytes(DH_P_BYTES, 'big')
# DH_G = 2

# class DHContext:
#     """A helper class to manage the state of a DH exchange."""
    
#     def __init__(self, g: int = DH_G, p: int = DH_P):
#         self.g = g
#         self.p = p
        
#         # 1. Generate DH parameters
#         pn = dh.DHParameterNumbers(p, g)
#         try:
#             self.parameters = pn.parameters(default_backend())
#         except ValueError:
#             # This can happen if p and g are invalid
#             print("Error: Invalid DH parameters (p, g). Using built-in generator.")
#             # Fallback to generating new params (slower)
#             self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
#             # Update p and g from the newly generated params
#             self.p = self.parameters.parameter_numbers().p
#             self.g = self.parameters.parameter_numbers().g

        
#         # 2. Generate our private key
#         self.private_key = self.parameters.generate_private_key()
        
#         # 3. Compute our public value (A or B)
#         self.public_value = self.private_key.public_key().public_numbers().y

#     def get_public_value(self) -> int:
#         """Returns this party's public value (A or B)."""
#         return self.public_value

#     def get_public_params(self) -> tuple[int, int]:
#         """Returns the public parameters (g, p)."""
#         return (self.g, self.p)

#     def compute_shared_key(self, peer_public_value: int) -> bytes:
#         """
#         Computes the shared secret (Ks) given the peer's public value.
#         Returns the raw shared secret Ks.
#         """
#         peer_pn = dh.DHPublicNumbers(peer_public_value, self.parameters.parameter_numbers())
#         peer_public_key = peer_pn.public_key(default_backend())
        
#         # Compute the shared secret
#         shared_secret_ks = self.private_key.exchange(peer_public_key)
#         return shared_secret_ks

#     @staticmethod
#     def derive_aes_key(shared_secret_ks: bytes) -> bytes:
#         """
#         Derives the final AES key K from the shared secret Ks.
#         K = Trunc16(SHA256(big-endian(Ks)))
        
#         Per PDF (Page 3 & 7): K = Trunc16(SHA256(big-endian(Ks)))
#         We will just hash Ks, as big-endian conversion is implicit in bytes.
#         """
#         # 1. K_hash = SHA256(Ks)
#         k_hash = sha256(shared_secret_ks).digest()
        
#         # 2. K = Trunc16(K_hash)
#         aes_key = k_hash[:16]
#         return aes_key


# """Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

# import os
# from hashlib import sha256
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import dh

# # Pre-defined DH parameters (Group 14, RFC 3526)
# # These are strong, well-known parameters.
# # We represent P as bytes and convert to an int, which is more robust.
# DH_P_BYTES = (
#     b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2\x21\x68\xC2\x34'
#     b'\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1\x29\x02\x4E\x08\x8A\x67\xCC\x74'
#     b'\x02\x0B\xBE\xA6\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD'
#     b'\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D\xF2\x5F\x14\x37'
#     b'\x4F\xE1\x35\x6D\x6D\x51\xC2\x45\xE4\x85\xB5\x76\x62\x5E\x7E\xC6'
#     b'\xF4\x4C\x42\xE9\xA6\x37\xED\x6B\x0B\xFF\x5C\xB6\xF4\x06\xB7\xED'
#     b'\xEE\x38\x6B\xFB\x5A\x89\x9F\xA5\xAE\x9F\x24\x11\x7C\x4B\x1F\xE6'
#     b'\x49\x28\x66\x51\xEC\xE4\x5B\x3D\xC2\x00\x7C\xB8\xA1\x63\xBF\x05'
#     b'\x98\xDA\x48\x36\x1C\x55\xD3\x9A\x69\x16\x3F\xA8\xFD\x24\xCF\x5F'
#     b'\x83\x65\x5D\x23\xDC\xA3\xAD\x96\x1C\x62\xF3\x56\x20\x85\x52\xBB'
#     b'\x9E\xD5\x29\x07\x70\x96\x96\x6D\x67\x0C\x35\x4E\x4A\xBC\x98\x04'
#     b'\xF1\x74\x6C\x08\xCA\x18\x21\x7C\x32\x90\x5E\x46\x2E\x36\xCE\x3B'
#     b'\xE3\x9E\x77\x2C\x18\x0E\x86\x03\x9B\x27\x83\xA2\xEC\x07\xA2\x8F'
#     b'\xB5\xC5\x5D\xF0\x6F\x4C\x52\xC9\xDE\x2B\xCB\xF6\x95\x58\x17\x18'
#     b'\x39\x95\x49\x7C\x45\xAE\x48\x5F\xD5\xB3\xE9\x6C\x3A\x67\x15\xDE'
#     b'\x43\x15\xD0\x07\x81\x63\x8B\x8E\x25\xF2\xF1\xCB\x5D\xF1\xC0\x11'
#     b'\x4B\xFB\x11\x8B\xF1\x58\x1C\x06\x65\x99\x48\xC8\x9E\x4B\x08\xF5'
#     b'\x83\x4F\x64\xFB\xF3\xDE\x36\x42\x0E\x8C\x82\x93\xA3\x51\x85\x9C'
#     b'\x81\x4B\x4F\x81\x13\x62\xE8\x9F\x73\x79\xCE\x8F\xDE\xF1\x21\x3A'
#     b'\x50\x00\x45\x61\x32\xAE\x1B\x7F\x53\x5E\xE7\x48\x83\xFC\x80\x2B'
#     b'\x86\xCF\xA6\x86\x27\x9C\x49\x8E\xEC\x1F\xAD\x3A\x8F\x27\x1A\xF3'
#     b'\x7B\x4B\x73\x71\xD7\x96\x4B\x7E\x6C\x8F\x9D\x3E\x70\x1C\x4D\x48'
#     b'\x6B\x0F\x84\x3B\x21\xDF\x14\x1B\x2A\xE0\x9A\xB6\x31\x3C\x3B\x98'
#     b'\xF5\x2D\x80\x32\x0A\x31\x7F\x7C\x47\x95\x3F\x89\x68\x8E\x95\x3A'
#     b'\xB5\x93\x8A\xF1\x2B\x73\x27\xBA\x77\x89\xAB\x13\x49\x7F\x5F\xAF'
#     b'\x6A\x27\x69\x0E\x17\x1D\x4C\x41\x1B\xF1\x1A\x04\x97\x64\x7D\x22'
#     b'\xF9\x04\x13\x1B\xDE\xFB\x8B\xF9\x7D\x54\x7A\xCD\x1B\xF7\x8B\x8A'
#     b'\xF1\xAE\x0A\x1C\x9E\x4F\x62\x7E\x6D\x61\x87\x0D\x49\x53\x1C\x01'
#     b'\x51\x40\x69\x40\x17\x92\x8F\x7C\x09\x20\x23\x74\x9B\x7E\x8F\x8C'
#     b'\x8B\x5F\x2A\x0A\x08\x9D\x7E\x3A\x48\xCC\x7F\x2C\x1E\x6F\x33\x3E'
#     b'\x83\x93\xBC\xF8\x24\x94\x28\x00\x1B\x6F\x3E\x4C\x4F\x0E\x0E\x1C'
#     b'\x5F\x73\x21\x80\x9F\x02\x47\x9B\x82\xFD\x84\x32\xE2\xAA\xFF\xFF'
#     b'\xFF\xFF\xFF\xFF\xFF\xFF'
# )

# DH_P = int.from_bytes(DH_P_BYTES, 'big')
# DH_G = 2

# class DHContext:
#     """A helper class to manage the state of a DH exchange."""
    
#     def __init__(self, g: int = DH_G, p: int = DH_P):
#         self.g = g
#         self.p = p
        
#         # 1. Generate DH parameters
#         pn = dh.DHParameterNumbers(p, g)
#         try:
#             self.parameters = pn.parameters(default_backend())
#         except ValueError:
#             # This can happen if p and g are invalid
#             print("Error: Invalid DH parameters (p, g). Using built-in generator.")
#             # Fallback to generating new params (slower)
#             self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
#             # Update p and g from the newly generated params
#             self.p = self.parameters.parameter_numbers().p
#             self.g = self.parameters.parameter_numbers().g

        
#         # 2. Generate our private key
#         self.private_key = self.parameters.generate_private_key()
        
#         # 3. Compute our public value (A or B)
#         self.public_value = self.private_key.public_key().public_numbers().y

#     def get_public_value(self) -> int:
#         """Returns this party's public value (A or B)."""
#         return self.public_value

#     def get_public_params(self) -> tuple[int, int]:
#         """Returns the public parameters (g, p)."""
#         return (self.g, self.p)

#     def compute_shared_key(self, peer_public_value: int) -> bytes:
#         """
#         Computes the shared secret (Ks) given the peer's public value.
#         Returns the raw shared secret Ks.
#         """
#         peer_pn = dh.DHPublicNumbers(peer_public_value, self.parameters.parameter_numbers())
#         peer_public_key = peer_pn.public_key(default_backend())
        
#         # Compute the shared secret
#         shared_secret_ks = self.private_key.exchange(peer_public_key)
#         return shared_secret_ks

#     @staticmethod
#     def derive_aes_key(shared_secret_ks: bytes) -> bytes:

#         # 1. K_hash = SHA256(Ks)
#         k_hash = sha256(shared_secret_ks).digest()
        
#         # 2. K = Trunc16(K_hash)
#         aes_key = k_hash[:16]
#         return aes_key


"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import os
from hashlib import sha256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

class DHContext:
    """A helper class to manage the state of a DH exchange."""
    
    def __init__(self, g: int | None = None, p: int | None = None):
        """
        Initialize DH context with optional g and p parameters.
        If not provided, generates 2048-bit DH parameters.
        """
        # If g and p are provided, use them; otherwise generate parameters
        if g is not None and p is not None:
            # 1. Create DH parameters from provided g and p
            try:
                pn = dh.DHParameterNumbers(p, g)
                self.parameters = pn.parameters(default_backend())
                self.g = g
                self.p = p
            except (ValueError, Exception) as e:
                raise ValueError(f"Invalid DH parameters (g={g}, p={p}): {e}")
        else:
            # 1. Generate standard 2048-bit DH parameters (Group 14/MODP 2048)
            # Use generator=2 and key_size=2048 for standard DH parameters
            self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            
            # Get g and p from the generated parameters
            self.g = self.parameters.parameter_numbers().g
            self.p = self.parameters.parameter_numbers().p
        
        # 2. Generate our private key
        self.private_key = self.parameters.generate_private_key()
        
        # 3. Compute our public value (A or B)
        self.public_value = self.private_key.public_key().public_numbers().y

    def get_public_value(self) -> int:
        """Returns this party's public value (A or B)."""
        return self.public_value

    def get_public_params(self) -> tuple[int, int]:
        """Returns the public parameters (g, p)."""
        return (self.g, self.p)

    def compute_shared_key(self, peer_public_value: int) -> bytes:
        """
        Computes the shared secret (Ks) given the peer's public value.
        Returns the raw shared secret Ks.
        """
        peer_pn = dh.DHPublicNumbers(peer_public_value, self.parameters.parameter_numbers())
        peer_public_key = peer_pn.public_key(default_backend())
        
        # Compute the shared secret
        shared_secret_ks = self.private_key.exchange(peer_public_key)
        return shared_secret_ks

    @staticmethod
    def derive_aes_key(shared_secret_ks: bytes) -> bytes:
        """
        Derives the final AES key K from the shared secret Ks.
        K = Trunc16(SHA256(big-endian(Ks)))
        """
        k_hash = sha256(shared_secret_ks).digest()
        aes_key = k_hash[:16]
        return aes_key