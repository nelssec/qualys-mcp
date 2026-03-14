# Eval Harness

Automated evaluation harness that scores the Qualys MCP server against 500 real-world customer questions.

## How it works

1. **Parser** (`parser.py`) — reads `docs/questions.md`, extracts questions with category/subcategory/coverage tags
2. **Runner** (`runner.py`) — connects to the MCP server via stdio, sends each question to Claude with all MCP tools available, runs an agentic loop (up to 10 tool-call iterations)
3. **Judge** (`judge.py`) — uses Claude-as-judge to score each response: `correct` / `partial` / `wrong` / `tool-error`
4. **Reporter** (`reporter.py`) — computes per-category scores, detects regressions vs prior runs, prints summary
5. **Updater** (`updater.py`) — rewrites coverage tags (✅/⚠️/❌) in `questions.md` based on scores

## Usage

```bash
# Required env vars
export QUALYS_USERNAME=...
export QUALYS_PASSWORD=...
export QUALYS_BASE_URL=...
export ANTHROPIC_API_KEY=...

# Run all 500 questions
python -m eval

# Quick smoke test (20 questions)
python -m eval --quick

# Filter by category
python -m eval --category "Vulnerability Management"

# Limit to N questions
python -m eval --limit 10

# Custom threshold (exit code 1 if below)
python -m eval --threshold 0.8

# Don't update questions.md tags
python -m eval --no-update

# Increase parallelism
python -m eval --concurrency 10
```

## Output

Results are saved to `eval_results/YYYY-MM-DD_HHMMSS.json` with:
- Metadata: timestamp, model, total questions, overall score
- Per-question detail: category, question, score, reasoning, tool calls, response snippet
- Per-category breakdown with scores

## Scoring

| Score | Weight | Meaning |
|-------|--------|---------|
| correct | 1.0 | Tool called, data returned, question answered well |
| partial | 0.5 | Tool called but data incomplete, or answer only partially addressed the question |
| wrong | 0.0 | Wrong tool called, or answer missed the point |
| tool-error | 0.0 | Tool exception, error, or no tool called when one should have been |

Overall score = (correct + 0.5 * partial) / total

## CI Integration

The `--threshold` flag makes the harness exit with code 1 if the score drops below the threshold, suitable for CI gates:

```bash
python -m eval --quick --threshold 0.7
```
