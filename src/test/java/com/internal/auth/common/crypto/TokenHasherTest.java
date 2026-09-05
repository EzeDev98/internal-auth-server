package com.internal.auth.common.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class TokenHasherTest {

    private final TokenHasher tokenHasher = new TokenHasher();

    @Test
    void sha256Hex_isDeterministic() {
        String hash1 = tokenHasher.sha256Hex("reset-token-value-987");
        String hash2 = tokenHasher.sha256Hex("reset-token-value-987");

        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    void sha256Hex_matchesKnownVector() {
        // Computed independently via Python's hashlib.sha256(...).hexdigest()
        // - not hand-typed from memory, since a wrong "known" vector would
        // make this test worse than useless.
        assertThat(tokenHasher.sha256Hex("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assertThat(tokenHasher.sha256Hex("reset-token-value-987"))
                .isEqualTo("0b43f5d94db035101bcae5d4c57e26b48a14cb7e3de70cf90f34fca1bbf23cbc");
    }

    @Test
    void sha256Hex_neverEqualsThePlaintextItHashes() {
        String raw = "a-raw-bearer-token-nobody-should-see-in-the-database";

        assertThat(tokenHasher.sha256Hex(raw)).isNotEqualTo(raw);
    }

    @Test
    void sha256Hex_isSixtyFourLowercaseHexCharacters() {
        String hash = tokenHasher.sha256Hex("any-input-works-for-a-shape-check");

        assertThat(hash).hasSize(64);
        assertThat(hash).matches("^[0-9a-f]{64}$");
    }

    @ParameterizedTest
    @CsvSource({
            "token-a, token-b",
            "123456, 654321",
            "'', not-empty"
    })
    void sha256Hex_differentInputsProduceDifferentHashes(String first, String second) {
        assertThat(tokenHasher.sha256Hex(first)).isNotEqualTo(tokenHasher.sha256Hex(second));
    }
}
