/*
 * seed_file.h — trusted seed from a provisioned file (example support)
 *
 * Mac OS 9 has no cryptographic RNG, so the example apps read a seed
 * that was generated elsewhere (tools/make_seed.sh) from the file named
 * kSeedFileName in the application's folder. Certainly cannot judge the
 * quality of the seed: its security is only as good as the machine that
 * generated it and the secrecy of the file.
 *
 * The file is replaced with fresh generator output as soon as it has
 * been read, so a seed is never used for two launches. If it cannot be
 * replaced the seed is discarded and no connection can be made.
 */

#ifndef CERTAINLY_EXAMPLE_SEED_FILE_H
#define CERTAINLY_EXAMPLE_SEED_FILE_H

/* Seed file name, as a Pascal string and in the messages below. */
#define kSeedFileName "Certainly Seed"

/*
 * Call after MacTLS_Init(). Returns NULL once MacTLS holds a trusted
 * seed, otherwise a short message suitable for a status line.
 *
 * On failure this calls MacTLS_Shutdown() so the consumed seed cannot be
 * used, which also drops any entropy provider the app had registered.
 * Apps that use a provider should not use this helper.
 */
const char *SeedFromFile(void);

#endif
