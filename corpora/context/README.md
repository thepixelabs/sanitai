# SanitAI Context Classification Corpus

Labeled conversation snippets for evaluating the `ContextClassifier`.

## Label definitions

- `real_paste`: User or assistant content containing an actual (or realistically real) secret value
- `educational`: Finding is in an example, tutorial, or format explanation
- `documentation_quote`: Finding comes from quoting official API documentation
- `model_hallucination`: Assistant generated a token that matches a pattern but is a well-known placeholder
- `unclassified`: Ambiguous; signals are contradictory or insufficient

## Structure

Each line in `index.jsonl` is a JSON object matching `schema.json`.

## Contributing

1. Add your entry to `index.jsonl` (one JSON object per line)
2. Ensure `expected_class` accurately reflects human judgment
3. Open a PR with a brief rationale in the description
4. Entries are reviewed like code — accuracy > quantity

## Evaluation

Run `tools/context-eval` to measure classifier precision/recall against this corpus.
Target gates: precision >= 0.90, recall >= 0.85 on `real_paste`.
