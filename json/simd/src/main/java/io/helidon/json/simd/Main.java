package io.helidon.json.simd;

import java.nio.charset.StandardCharsets;

import jdk.incubator.vector.ByteVector;
import jdk.incubator.vector.VectorShuffle;

import static jdk.incubator.vector.ByteVector.SPECIES_512;

public class Main {

    private static final long EVEN_BITS_MASK = 0x5555555555555555L;
    private static final long ODD_BITS_MASK = ~EVEN_BITS_MASK;

    // ---------------------------------------------------------------------------
    // Whitespace table — indexed by low nibble of the input byte.
    // Each slot holds the ACTUAL whitespace char that has that low nibble,
    // or a dummy value that can never match a real byte at that slot.
    //
    // '\t' = 0x09  → slot 9
    // '\n' = 0x0A  → slot A
    // '\r' = 0x0D  → slot D
    // ' '  = 0x20  → slot 0
    //
    // Dummy = 100 (0x64). A byte with low nibble N would need to equal 0x64
    // to false-positive, but 0x64 has low nibble 4, not matching its own slot.
    // ---------------------------------------------------------------------------
    private static final ByteVector WHITESPACE_TABLE;

    // ---------------------------------------------------------------------------
    // Structural character table — indexed by low nibble of (byte | 0x20).
    // OR-ing with 0x20 collapses bracket pairs:
    //   '[' (0x5B) | 0x20 = 0x7B = '{'
    //   ']' (0x5D) | 0x20 = 0x7D = '}'
    // So one table entry covers both '[' and '{', and both ']' and '}'.
    //
    // After OR: '{' = 0x7B → low nibble B
    //           '}' = 0x7D → low nibble D
    //           ':' = 0x3A → low nibble A
    //           ',' = 0x2C → low nibble C
    // ---------------------------------------------------------------------------
    private static final ByteVector STRUCTURAL_TABLE;

    static {
        byte x = (byte) 0x80; // dummy — cannot match any real byte at the wrong slot

        byte[] ws = new byte[] {
                ' ', x, x, x, x, x, x, x,          // 0-7
                x, '\t', '\n', x, x, '\r', x, x    // 8-F
        };

        byte[] st = new byte[] {
                x, x, x, x, x, x, x, x,           // 0-7
                x, x, ':', '{', ',', '}', x, x    // 8-F
        };

        WHITESPACE_TABLE  = ByteVector.fromArray(SPECIES_512, tile(ws), 0);
        STRUCTURAL_TABLE  = ByteVector.fromArray(SPECIES_512, tile(st), 0);
    }

    // ---------------------------------------------------------------------------
    // Tile a 16-byte lookup table to fill the full vector width.
    // SPECIES_512 = 64 bytes = 4 × 16-byte lanes.
    // Each 128-bit lane needs its own copy because vpshufb operates per-lane.
    // ---------------------------------------------------------------------------
    private static byte[] tile(byte[] src16) {
        int copies = SPECIES_512.vectorByteSize() / 16;  // 4 for 512, 2 for 256
        byte[] dst = new byte[SPECIES_512.vectorByteSize()];
        for (int i = 0; i < copies; i++) {
            System.arraycopy(src16, 0, dst, i * 16, 16);
        }
        return dst;
    }

    public static void main(String[] args) {
        System.out.println("     " + binary(EVEN_BITS_MASK));
        System.out.println("     " + binary(ODD_BITS_MASK));
        //        String json = "{ \"\\\\\\\"Nam[{\": [ 116,\"\\\\\\\\ \" , 234 , \"true\", false ], \"t\":\"\\\\\\\"\" }";
        String json = "{ \"Ahoj-k,amo\": [ 116,\"te \\nticek\" , 234 , \"true\", false ], \"testickovej\" }".repeat(3);
        System.out.println("     " + json);
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ByteVector chunk = ByteVector.fromArray(SPECIES_512, bytes, 0);

        long identifiedBackslashes = chunk.eq((byte) '\\').toLong(); //B
        long previousChunkBackslash = 0;
        long escaped = 0;
        long prevInString = 0;

        if (identifiedBackslashes == 0) {
            //No backslashes identified in the checked range
        } else {

//            long followsEscape = identifiedBackslashes << 1 | 0;
//            long oddSequenceStarts = identifiedBackslashes & ODD_BITS_MASK & ~followsEscape;
//
//            long sequencesStartingOnEvenBits = oddSequenceStarts + identifiedBackslashes;
//            long invertMask = sequencesStartingOnEvenBits << 1;
//            escaped = (EVEN_BITS_MASK ^ invertMask) & followsEscape;
//            System.out.println("EE:  " + binary(escaped));


            //Escape detected
            System.out.println("B:   " + binary(identifiedBackslashes));
            // identify ’starts ’ - backslashes characters not preceded by backslashes
            long S = identifiedBackslashes & ~(identifiedBackslashes << 1); //S
            System.out.println("S:   " + binary(S));
            // detect end of a odd - length sequence of backslashes starting on an even offset
            // detail : ES gets all ’starts ’ that begin on even offsets
            long ES = S & EVEN_BITS_MASK; //ES
            System.out.println("ES:  " + binary(ES));
            // add B to ES , yielding carries on backslash sequences with even starts
            long EC = identifiedBackslashes + ES; //EC
            System.out.println("EC:  " + binary(EC));
            // filter out the backslashes from the previous addition , getting carries only
            long ECE = EC & ~identifiedBackslashes;
            System.out.println("ECE: " + binary(ECE));
            // select only the end of sequences ending on an odd offset
            long OD1 = ECE & ODD_BITS_MASK;
            System.out.println("OD1: " + binary(OD1));
            // detect end of a odd - length sequence of backslashes starting on an odd offset
            // details are as per the above sequence
            long OS = S & ODD_BITS_MASK;
            System.out.println("OS:  " + binary(OS));
            long OC = identifiedBackslashes + OS;
            System.out.println("OC:  " + binary(OC));
            long OCE = OC & ~identifiedBackslashes;
            System.out.println("OCE: " + binary(OCE));
            long OD2 = OCE & EVEN_BITS_MASK;
            System.out.println("OD2: " + binary(OD2));

            // merge results , yielding ends of all odd - length sequence of backslashes
            escaped = OD1 | OD2; //escaped name?? in simdjson-java??
            System.out.println("OD:  " + binary(escaped));
        }

        //Identify Strings
        long Q = chunk.eq((byte) '\"').toLong(); //Q
        System.out.println("Q:   " + binary(Q));
        Q = Q & ~escaped;
        System.out.println("Q:   " + binary(Q));

        long stringRanges = prefixXor(Q) ^ prevInString;
        prevInString = stringRanges >> 63;
        System.out.println("R:   " + binary(stringRanges));

        //Extract the low nibble information
        VectorShuffle<Byte> lowNibble = chunk.and((byte) 0x0F).toShuffle();
        // Shuffle: look up each nibble in the table
        long whitespaces = chunk.eq(WHITESPACE_TABLE.rearrange(lowNibble)).toLong();
        System.out.println("W:   " + binary(whitespaces));

        //Setting bit 5 (0x20) is the ASCII trick that converts uppercase to lowercase
        //This converts [ ] and to { }
        long structural = chunk.or((byte) 0x20).eq(STRUCTURAL_TABLE.rearrange(lowNibble)).toLong();
        System.out.println("S:   " + binary(structural));

        // eliminate quoted regions from our structural characters
        long withoutQuoted = structural & ~stringRanges;
        System.out.println("S:   " + binary(withoutQuoted));

        // restore ending quotes to our structural characters
        // ( for purposes of building pseudo - structural characters )
        long endingQuotes = withoutQuoted | Q;
        System.out.println("S:   " + binary(endingQuotes));

        // begin to calculate pseudo - structural characters
        // initially ; pseudo - structural characters are structural or white space
        long pseudoStructuralChars = endingQuotes | whitespaces;
        System.out.println("P:   " + binary(pseudoStructuralChars));

        // now move our mask for candidate pseudo - structural characters forward by one
        long maskMoved = pseudoStructuralChars << 1;
        System.out.println("P:   " + binary(maskMoved));

        // eliminate white-space and quoted characters from our candidates
        long eliminatedWhiteAndQuoted = maskMoved & ~whitespaces & ~stringRanges;
        System.out.println("P:   " + binary(eliminatedWhiteAndQuoted));

        // merge pseudo - structural characters into structural character mask
        long mergedPseudoStructuralChars = endingQuotes | eliminatedWhiteAndQuoted;
        System.out.println("S:   " + binary(mergedPseudoStructuralChars));

        // eliminate ending quotes from our final structural characters
        long fin = mergedPseudoStructuralChars & ~(Q & ~stringRanges);
        System.out.println("FIN: " + binary(fin));

    }

    private static long prefixXor(long bitmask) {
        bitmask ^= bitmask << 1;
        bitmask ^= bitmask << 2;
        bitmask ^= bitmask << 4;
        bitmask ^= bitmask << 8;
        bitmask ^= bitmask << 16;
        bitmask ^= bitmask << 32;
        return bitmask;
    }

    public static String binary(long myLong) {
        StringBuilder sb = new StringBuilder(64);

        for (int i = 0; i < 64; i++) {
            // Check if the lowest bit is 1 or 0
            sb.append((myLong & 1) == 1 ? '1' : '0');

            // Logical right shift to bring the next bit into the lowest position
            myLong >>>= 1;
        }

        return sb.toString();
    }

}
