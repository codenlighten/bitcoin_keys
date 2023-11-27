#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/sha.h>
#include "secp256k1.h"
#include "libbase58.h"

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

bool my_sha256(void *digest, const void *data, size_t datasz) {
    return SHA256(data, datasz, digest);
}

void sign_message(const secp256k1_context *ctx, const unsigned char *priv_key, const unsigned char *message, size_t message_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(message, message_len, hash);

    secp256k1_ecdsa_signature signature;
    if (secp256k1_ecdsa_sign(ctx, &signature, hash, priv_key, NULL, NULL) == 1) {
        unsigned char serialized_sig[72];
        size_t serialized_sig_len = sizeof(serialized_sig);
        secp256k1_ecdsa_signature_serialize_der(ctx, serialized_sig, &serialized_sig_len, &signature);

        printf("Signature: ");
        print_hex(serialized_sig, serialized_sig_len);
    } else {
        printf("Failed to sign the message.\n");
    }
}

int main() {
    // Load the default and legacy providers
    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    OSSL_PROVIDER *default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!legacy || !default_provider) {
        fprintf(stderr, "Failed to load OpenSSL providers.\n");
        return 1;
    }

    // Set SHA256 implementation for libbase58
    b58_sha256_impl = my_sha256;

    EVP_MD_CTX *mdctx;
    const EVP_MD *sha256_md;
    const EVP_MD *ripemd160_md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned char sha256_result[EVP_MAX_MD_SIZE]; // Declare sha256_result
    unsigned int md_len, sha256_len;
    unsigned char address[25];

    // Fetch the SHA-256 and RIPEMD-160 algorithms
    sha256_md = EVP_MD_fetch(NULL, "SHA256", NULL);
    ripemd160_md = EVP_MD_fetch(NULL, "RIPEMD160", NULL);
    if (!sha256_md || !ripemd160_md) {
        fprintf(stderr, "Failed to fetch digest.\n");
        return 1;
    }

    // Initialize secp256k1 context and generate keys
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char priv_key[32];
    FILE *frand = fopen("/dev/urandom", "rb");
    if (fread(priv_key, 1, sizeof(priv_key), frand) != sizeof(priv_key)) {
        fprintf(stderr, "Error reading random data.\n");
        fclose(frand);
        return 1;
    }
    fclose(frand);

    printf("Private Key: ");
    print_hex(priv_key, sizeof(priv_key));

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key)) {
        fprintf(stderr, "Failed to create public key.\n");
        return 1;
    }

    unsigned char serialized_pubkey[65];
    size_t serialized_pubkey_len = sizeof(serialized_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &serialized_pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        fprintf(stderr, "Failed to serialize public key.\n");
        return 1;
    }

    printf("Public Key: ");
    print_hex(serialized_pubkey, serialized_pubkey_len);

    // Hash the public key with SHA-256, then RIPEMD-160
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, sha256_md, NULL);
    EVP_DigestUpdate(mdctx, serialized_pubkey, serialized_pubkey_len);
    EVP_DigestFinal_ex(mdctx, sha256_result, &sha256_len);
    EVP_DigestInit_ex(mdctx, ripemd160_md, NULL);
    EVP_DigestUpdate(mdctx, sha256_result, sha256_len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    printf("RIPEMD-160 Hash: ");
    print_hex(md_value, md_len);

    // Add version byte and compute checksum
    unsigned char checksum[SHA256_DIGEST_LENGTH];
    address[0] = 0x00; // Version byte for mainnet
    memcpy(address + 1, md_value, md_len);
    SHA256(address, 21, checksum);
    SHA256(checksum, SHA256_DIGEST_LENGTH, checksum);
    memcpy(address + 21, checksum, 4);

    // Base58Check encoding
    char base58check[50]; // Increased buffer size
    size_t base58check_size = sizeof(base58check);
    if (!b58check_enc(base58check, &base58check_size, 0, address, 25)) {
        fprintf(stderr, "Base58Check encoding failed.\n");
        return 1;
    }
    printf("Bitcoin Address: %s\n", base58check);
    // Example message to be signed
    const char *message = "Hello, world!";
    printf("Signing message: \"%s\"\n", message);
    sign_message(ctx, priv_key, (const unsigned char *)message, strlen(message));
    // Cleanup
    EVP_MD_free((EVP_MD*)sha256_md);
    EVP_MD_free((EVP_MD*)ripemd160_md);
    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(default_provider);
    secp256k1_context_destroy(ctx);
    return 0;
}

