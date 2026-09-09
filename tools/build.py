"""Generate SPL and review artifacts from the repository's limited JSON rule schema."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load_rules():
    return [json.loads(p.read_text(encoding='utf-8')) for p in sorted((ROOT/'rules').glob('*/*.json'))]

def literal(value):
    return json.dumps(value, ensure_ascii=False)

def spl(rule):
    clauses = [f'isnotnull({f})' for f in rule['required_fields']]
    for field, op, value in rule['conditions']:
        if op == 'eq':
            clauses.append(f'{field}={literal(value)}')
        elif op == 'regex':
            clauses.append(f'match({field}, {literal(value)})')
        else:
            raise ValueError(op)
    metric = 'count' if rule['metric']=='count' else f"dc({rule['metric']})"
    return (f'index=detection_lab log_type="{rule["log_source"]}" earliest=-10m@m latest=-5m@m\n'
            + '| where ' + ' AND '.join(clauses) + '\n'
            + f'| stats {metric} as observed min(_time) as first_seen max(_time) as last_seen by ' + ' '.join(rule['group_by']) + '\n'
            + f'| where observed >= {rule["threshold"]}\n'
            + f'| eval rule_id="{rule["id"]}", attack_id="{rule["attack_id"]}"\n')

def artifacts(rules):
    result={}
    matrix='# ATT&CK × ログ（候補カバレッジ）\n\n各セルは技法の一部を観測するルールへのリンクです。状態は各カードを参照。未記載技法は未評価です。\n\n|Tactic|Technique|Windows Event|FW|Proxy|NDR|\n|---|---|---|---|---|---|\n'
    groups={}
    for r in rules:
        result[f'queries/{r["id"]}.spl']=spl(r)
        result[f'docs/rules/{r["id"]}.md']=(f'# {r["id"]} {r["title"]}\n\n'
          + f'- 状態：{r["status"]} / 重要度：{r["level"]}\n- ATT&CK：{r["attack_id"]} / {r["tactic"]}\n'
          + f'- 対象ログ：{r["log_source"]}\n- 必須フィールド：'+', '.join(r['required_fields'])+'\n'
          + f'- 窓：{r["window_seconds"]}秒（検索範囲全体） / 集約：'+', '.join(r['group_by'])+'\n'
          + f'- 指標：{r["metric"]}（count以外は異なる値の数） / 閾値：{r["threshold"]}以上\n\n'
          + f'## 採取の前提\n\n{r["prerequisites"]}\n\n## 誤検知と調整\n\n{r["false_positives"]}\n\n'
          + f'## 調査\n\n{r["triage"]}\n\n## 限界\n\n{r["limitations"]}\n\n'
          + '## 条件（すべてAND）\n\n```json\n'+json.dumps(r['conditions'],ensure_ascii=False,indent=2)+'\n```\n\n'
          + '## SPL\n\n[検索ファイル](../../queries/'+r['id']+'.spl)。正規化と導入手順は[こちら](../deployment.md)。\n\n'
          + '## 参考\n\n'+'\n'.join(f'- [参考資料 {i+1}]({url})' for i,url in enumerate(r['references']))+'\n')
        groups.setdefault((r['tactic'],r['attack_id']),[]).append(r)
    for (tactic,tech),rr in sorted(groups.items()):
        cells=[' / '.join(f'[{r["id"]}](rules/{r["id"]}.md)' for r in rr if r['log_source']==s) or '—' for s in ['windows','fw','proxy','ndr']]
        matrix += '|'+tactic+'|'+tech+'|'+'|'.join(cells)+'|\n'
    result['docs/matrix.md']=matrix
    return result

if __name__=='__main__':
    rules=load_rules()
    for path, content in artifacts(rules).items():
        p=ROOT/path
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(content,encoding='utf-8')
    print(f'Generated artifacts for {len(rules)} rules')
