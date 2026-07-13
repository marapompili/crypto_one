import hashlib
from pathlib import Path
from typing import Iterator

BLOCK_SIZE = 1024
HASH_SIZE = 32  # SHA-256 produces a 32-byte hash


def read_blocks(filename: str) -> list[bytes]:
    """
    Read a binary file and split it into 1024-byte blocks.
    The last block may be smaller than 1024 bytes.
    """
    path = Path(filename)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {filename}")

    blocks: list[bytes] = []

    with path.open("rb") as file:
        while True:
            block = file.read(BLOCK_SIZE)

            if not block:
                break

            blocks.append(block)

    if not blocks:
        raise ValueError("The file is empty.")

    return blocks


def compute_h0(filename: str) -> bytes:
    """
    Compute the initial hash h0.

    Formula:
        h_last = SHA256(B_last)
        h_i = SHA256(B_i || h_(i+1))
    """
    blocks = read_blocks(filename)

    current_hash = b""

    # Process blocks from the end of the file to the beginning
    for block in reversed(blocks):
        current_hash = hashlib.sha256(
            block + current_hash
        ).digest()

    return current_hash


def create_authenticated_chunks(filename: str) -> list[bytes]:
    """
    Create the authenticated chunks that the server would send.

    For every block except the last:
        B_i || h_(i+1)

    For the last block:
        B_last
    """
    blocks = read_blocks(filename)
    authenticated_chunks: list[bytes] = [b""] * len(blocks)

    next_hash = b""

    for index in range(len(blocks) - 1, -1, -1):
        block = blocks[index]

        if index == len(blocks) - 1:
            authenticated_chunks[index] = block
        else:
            authenticated_chunks[index] = block + next_hash

        next_hash = hashlib.sha256(
            block + next_hash
        ).digest()

    return authenticated_chunks


def verify_authenticated_chunks(
    chunks: Iterator[bytes],
    authenticated_h0: bytes,
) -> Iterator[bytes]:
    """
    Verify the received authenticated chunks.

    Yields authenticated video blocks.
    Raises ValueError if any block has been modified.
    """
    chunks_list = list(chunks)

    if not chunks_list:
        raise ValueError("No chunks received.")

    expected_hash = authenticated_h0

    for index, chunk in enumerate(chunks_list):
        is_last_chunk = index == len(chunks_list) - 1

        if is_last_chunk:
            video_block = chunk
            next_hash = b""
        else:
            if len(chunk) < HASH_SIZE:
                raise ValueError(
                    f"Chunk {index} is too short to contain the next hash."
                )

            video_block = chunk[:-HASH_SIZE]
            next_hash = chunk[-HASH_SIZE:]

        calculated_hash = hashlib.sha256(
            video_block + next_hash
        ).digest()

        if calculated_hash != expected_hash:
            raise ValueError(
                f"Authentication failed for chunk {index}."
            )

        yield video_block

        # The next expected hash is the hash carried in the current chunk
        expected_hash = next_hash


def main() -> None:
    filename = input("Enter the video file path: ").strip()

    try:
        h0 = compute_h0(filename)

        print("\nh0 (hexadecimal):")
        print(h0.hex())

        # Simulate the chunks prepared by the server
        authenticated_chunks = create_authenticated_chunks(filename)

        # Simulate client-side verification
        verified_data = bytearray()

        for verified_block in verify_authenticated_chunks(
            iter(authenticated_chunks),
            h0,
        ):
            verified_data.extend(verified_block)

        # Verify that the reconstructed data matches the original file
        original_data = Path(filename).read_bytes()

        if bytes(verified_data) == original_data:
            print("\nAll chunks were successfully verified.")
        else:
            print("\nError: reconstructed data does not match the original file.")

    except (FileNotFoundError, ValueError, OSError) as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()