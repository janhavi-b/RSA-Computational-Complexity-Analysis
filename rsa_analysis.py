
import csv
import os
import statistics
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


KEY_SIZES = [1024, 2048, 3072, 4096]
REPEATS = 5
MESSAGE = b"RSA computational complexity analysis project"

OUTPUT_DIR = "results"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def measure_time(operation):
    start = time.perf_counter()
    result = operation()
    elapsed_ms = (time.perf_counter() - start) * 1000
    return result, elapsed_ms


def run_experiment():
    all_results = []

    print("\nRSA Computational Complexity Analysis", flush=True)
    print("=" * 60, flush=True)

    for key_size in KEY_SIZES:
        print(f"\nTesting RSA key size: {key_size} bits", flush=True)

        keygen_times = []
        encryption_times = []
        decryption_times = []

        for run in range(REPEATS):
            private_key, keygen_ms = measure_time(
                lambda: rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size
                )
            )

            public_key = private_key.public_key()

            ciphertext, encryption_ms = measure_time(
                lambda: public_key.encrypt(
                    MESSAGE,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            )

            plaintext, decryption_ms = measure_time(
                lambda: private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            )

            assert plaintext == MESSAGE

            keygen_times.append(keygen_ms)
            encryption_times.append(encryption_ms)
            decryption_times.append(decryption_ms)

            print(
                f"Run {run + 1}: "
                f"Keygen={keygen_ms:.3f} ms, "
                f"Encrypt={encryption_ms:.3f} ms, "
                f"Decrypt={decryption_ms:.3f} ms",
                flush=True
            )

        result = {
            "key_size_bits": key_size,
            "runs": REPEATS,
            "avg_keygen_ms": statistics.mean(keygen_times),
            "avg_encrypt_ms": statistics.mean(encryption_times),
            "avg_decrypt_ms": statistics.mean(decryption_times),
            "median_keygen_ms": statistics.median(keygen_times),
            "median_encrypt_ms": statistics.median(encryption_times),
            "median_decrypt_ms": statistics.median(decryption_times),
        }

        all_results.append(result)

        print(
            f"Average times: "
            f"Keygen={result['avg_keygen_ms']:.3f} ms, "
            f"Encrypt={result['avg_encrypt_ms']:.3f} ms, "
            f"Decrypt={result['avg_decrypt_ms']:.3f} ms",
            flush=True
        )

    return all_results


def save_csv(results):
    output_file = os.path.join(OUTPUT_DIR, "rsa_results.csv")

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"\nResults saved to: {output_file}", flush=True)


def create_graphs(results):
    key_sizes = [r["key_size_bits"] for r in results]

    operations = [
        ("avg_keygen_ms", "Key Generation", "key_generation_time.png"),
        ("avg_encrypt_ms", "Encryption", "encryption_time.png"),
        ("avg_decrypt_ms", "Decryption", "decryption_time.png"),
    ]

    for column, title, filename in operations:
        times = [r[column] for r in results]

        plt.figure(figsize=(8, 5))
        plt.plot(key_sizes, times, marker="o")
        plt.xlabel("RSA Key Size (bits)")
        plt.ylabel("Average Execution Time (ms)")
        plt.title(f"RSA {title} Time vs Key Size")
        plt.xticks(key_sizes)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()

        path = os.path.join(OUTPUT_DIR, filename)
        plt.savefig(path, dpi=150)
        plt.close()

        print(f"Graph saved to: {path}", flush=True)


if __name__ == "__main__":
    results = run_experiment()
    save_csv(results)
    create_graphs(results)

    print("\nAll experiments completed successfully!", flush=True)