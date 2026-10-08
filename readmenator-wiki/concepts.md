# Concepts

Second-brain semantic layer: nouns map atomically to file sets (EXTRACTED); verbs aggregate structural edges (INFERRED).

| Concept | Files | Mentions | Top Files |
|---------|-------|----------|-----------|
| `gen` | 4 | 8 | `gen_ebird3.sh`, `gen_hellbird.sh`, `gen_hellbird2.sh`, `gen_hellbird3.sh` |
| `xor` | 4 | 8 | `gen_ebird3.sh`, `gen_hellbird.sh`, `gen_hellbird2.sh`, `gen_hellbird3.sh` |
| `string` | 4 | 5 | `gen_ebird3.sh`, `gen_hellbird.sh`, `gen_hellbird2.sh`, `gen_hellbird3.sh` |
| `usage` | 4 | 4 | `gen_ebird3.sh`, `gen_hellbird.sh`, `gen_hellbird2.sh`, `gen_hellbird3.sh` |
| `hellbird` | 3 | 5 | `gen_hellbird.sh`, `gen_hellbird2.sh`, `gen_hellbird3.sh` |
| `array` | 3 | 3 | `gen_ebird3.sh`, `gen_hellbird.sh`, `gen_hellbird2.sh` |
| `configuraci` | 3 | 3 | `gen_hellbird.sh`, `gen_hellbird2.sh`, `gen_hellbird3.sh` |
| `funci` | 3 | 3 | `gen_ebird3.sh`, `gen_hellbird.sh`, `gen_hellbird2.sh` |
| `uso` | 3 | 3 | `gen_hellbird.sh`, `gen_hellbird2.sh`, `gen_hellbird3.sh` |

## Dialectic Prompts

- Thesis: `array` centralizes 3 files; Antithesis: `configuraci` pulls 3 files with 2 shared (Jaccard 0.50); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `array` centralizes 3 files; Antithesis: `funci` pulls 3 files with 3 shared (Jaccard 1.00); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `array` centralizes 3 files; Antithesis: `gen` pulls 4 files with 3 shared (Jaccard 0.75); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `array` centralizes 3 files; Antithesis: `hellbird` pulls 3 files with 2 shared (Jaccard 0.50); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `array` centralizes 3 files; Antithesis: `string` pulls 4 files with 3 shared (Jaccard 0.75); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `array` centralizes 3 files; Antithesis: `usage` pulls 4 files with 3 shared (Jaccard 0.75); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `array` centralizes 3 files; Antithesis: `uso` pulls 3 files with 2 shared (Jaccard 0.50); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `array` centralizes 3 files; Antithesis: `xor` pulls 4 files with 3 shared (Jaccard 0.75); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `configuraci` centralizes 3 files; Antithesis: `funci` pulls 3 files with 2 shared (Jaccard 0.50); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `configuraci` centralizes 3 files; Antithesis: `gen` pulls 4 files with 3 shared (Jaccard 0.75); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
