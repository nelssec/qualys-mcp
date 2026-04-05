#!/bin/bash
# Run routing eval against Claude headless mode with MCP tools
# Tests that Claude picks the right workflow tool for each question
#
# Usage: ./eval/run_routing_eval.sh [--limit N] [--sample N]

set -euo pipefail

LIMIT=${1:-50}
RESULTS_FILE="eval_results/routing_$(date +%Y%m%d_%H%M%S).jsonl"
SUMMARY_FILE="eval_results/routing_summary_$(date +%Y%m%d_%H%M%S).json"
mkdir -p eval_results

echo "=== Qualys MCP Routing Eval ==="
echo "Questions: $LIMIT"
echo "Results: $RESULTS_FILE"
echo ""

python3 -c "
import json, random, subprocess, sys, time

with open('/tmp/qualys_eval_questions.json') as f:
    all_q = json.load(f)

limit = int('$LIMIT')
if limit < len(all_q):
    random.seed(42)
    sample = random.sample(all_q, limit)
else:
    sample = all_q

results = []
correct = 0
wrong = 0
errors = 0
total = len(sample)

VALID_TOOLS = {'investigate', 'assess_risk', 'check_compliance', 'plan_remediation', 'security_overview', 'reports', 'cache_status'}

for i, q in enumerate(sample):
    qtext = q['question'].replace('\"', '\\\\\"')
    prompt = f'Answer this security question using the qualys MCP tools. Only call ONE tool. Question: {qtext}'

    try:
        result = subprocess.run(
            ['claude', '-p', '--output-format', 'json', '--max-turns', '2', '--max-budget-usd', '0.05',
             prompt],
            capture_output=True, text=True, timeout=60,
            cwd='$PWD'
        )

        output = result.stdout.strip()
        if output:
            try:
                resp = json.loads(output)
                # Check which tool was called
                tool_used = None
                for msg in resp.get('messages', []):
                    if msg.get('role') == 'assistant':
                        for content in msg.get('content', []):
                            if content.get('type') == 'tool_use':
                                tool_used = content.get('name', '')
                                break
                    if tool_used:
                        break

                if not tool_used:
                    text = resp.get('result', '')
                    for t in VALID_TOOLS:
                        if t in text.lower():
                            tool_used = t
                            break

                is_correct = tool_used == q['expected']
                if is_correct:
                    correct += 1
                    status = 'PASS'
                elif tool_used:
                    wrong += 1
                    status = 'FAIL'
                else:
                    errors += 1
                    status = 'NO_TOOL'

                entry = {
                    'id': q['id'],
                    'question': q['question'][:80],
                    'expected': q['expected'],
                    'actual': tool_used,
                    'correct': is_correct,
                    'status': status,
                    'type': q['type'],
                    'category': q['category'],
                }
                results.append(entry)

                pct = (correct / (i+1)) * 100
                print(f'[{i+1:>4}/{total}] {status:7} exp={q[\"expected\"]:<20} got={str(tool_used):<20} | {q[\"question\"][:50]}', flush=True)

            except json.JSONDecodeError:
                errors += 1
                results.append({'id': q['id'], 'status': 'JSON_ERROR', 'expected': q['expected']})
                print(f'[{i+1:>4}/{total}] JSON_ERR | {q[\"question\"][:50]}', flush=True)
        else:
            errors += 1
            results.append({'id': q['id'], 'status': 'EMPTY', 'expected': q['expected']})
            print(f'[{i+1:>4}/{total}] EMPTY    | {q[\"question\"][:50]}', flush=True)

    except subprocess.TimeoutExpired:
        errors += 1
        results.append({'id': q['id'], 'status': 'TIMEOUT', 'expected': q['expected']})
        print(f'[{i+1:>4}/{total}] TIMEOUT  | {q[\"question\"][:50]}', flush=True)
    except Exception as e:
        errors += 1
        results.append({'id': q['id'], 'status': 'ERROR', 'expected': q['expected'], 'error': str(e)[:100]})
        print(f'[{i+1:>4}/{total}] ERROR    | {q[\"question\"][:50]} — {str(e)[:40]}', flush=True)

# Write results
with open('$RESULTS_FILE', 'w') as f:
    for r in results:
        f.write(json.dumps(r) + '\n')

# Summary
accuracy = correct / total * 100 if total else 0
summary = {
    'total': total,
    'correct': correct,
    'wrong': wrong,
    'errors': errors,
    'accuracy': round(accuracy, 1),
    'by_workflow': {},
    'by_category': {},
}

from collections import Counter
for wf in ['investigate', 'assess_risk', 'check_compliance', 'plan_remediation', 'security_overview']:
    wf_results = [r for r in results if r.get('expected') == wf]
    wf_correct = sum(1 for r in wf_results if r.get('correct'))
    summary['by_workflow'][wf] = {
        'total': len(wf_results),
        'correct': wf_correct,
        'accuracy': round(wf_correct / len(wf_results) * 100, 1) if wf_results else 0,
    }

with open('$SUMMARY_FILE', 'w') as f:
    json.dump(summary, f, indent=2)

print(f'\n{\"=\"*60}')
print(f'ROUTING EVAL RESULTS')
print(f'{\"=\"*60}')
print(f'Total: {total} | Correct: {correct} | Wrong: {wrong} | Errors: {errors}')
print(f'Accuracy: {accuracy:.1f}%')
print(f'\nBy workflow:')
for wf, data in summary['by_workflow'].items():
    print(f'  {wf:<25} {data[\"correct\"]}/{data[\"total\"]} ({data[\"accuracy\"]}%)')
print(f'\nResults: $RESULTS_FILE')
print(f'Summary: $SUMMARY_FILE')
"
