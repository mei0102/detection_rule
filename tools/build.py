"""Generate SPL and review artifacts from the repository's limited JSON rule schema."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load_attack():
    return json.loads((ROOT/'data/attack.json').read_text(encoding='utf-8'))

def load_rules():
    return [json.loads(p.read_text(encoding='utf-8')) for p in sorted((ROOT/'rules').glob('*/*.json'))]

def literal(value):
    return json.dumps(value, ensure_ascii=False)

def spl(rule):
    clauses = [f'isnotnull({f})' for f in rule['required_fields']]
    for field, op, value in rule['conditions']:
        if op == '=':
            clauses.append(f'{field}={literal(value)}')
        elif op == '~=':
            clauses.append(f'match({field}, {literal(value)})')
        else:
            raise ValueError(op)
    metric = 'count' if rule['metric']=='count' else f"dc({rule['metric']})"
    return (f'index=detection_lab log_type="{rule["log_source"]}" earliest=-10m@m latest=-5m@m\n'
            + '| where ' + '\n    AND '.join(clauses) + '\n'
            + f'| stats {metric} as observed min(_time) as first_seen max(_time) as last_seen by ' + ' '.join(rule['group_by']) + '\n'
            + f'| where observed >= {rule["threshold"]}\n'
            + f'| eval rule_id="{rule["id"]}", attack_id="{rule["attack_id"]}"\n')

def link(obj):
    return f'[{obj["id"]} {obj["name"]}]({obj["url"]})'

def position(rule, attack):
    tech=attack['techniques'][rule['attack_id']]
    parent=attack['techniques'][rule['attack_id'].split('.')[0]]
    lines=['|戦術（Matrixの列）|親技法|サブ技法|本ルールとの関係|','|---|---|---|---|']
    for tactic in attack['tactics']:
        if tactic['slug'] in rule['attack_tactics']:
            relation='主な検知仮説' if tactic['slug']==rule['tactic'] else '公式の関連列（結果の成立までは判定しない）'
            lines.append('|'+link(tactic)+'|'+link(parent)+'|'+(link(tech) if '.' in rule['attack_id'] else 'なし（親技法に対応）')+'|'+relation+'|')
    return '\n'.join(lines)+'\n'

def conditions(rule):
    lines=[f'log_type = {literal(rule["log_source"])}']
    # A plain-text formula has raw regular expressions, not JSON-escaped arrays.
    lines += [f'{field} {op} '+(f'/{value}/' if op=='~=' else literal(value)) for field,op,value in rule['conditions']]
    metric='count(*)' if rule['metric']=='count' else f'dc({rule["metric"]})'
    return '\nAND '.join(lines)+f'\n\nGROUP BY '+', '.join(rule['group_by'])+f'\nWINDOW = {rule["window_seconds"]} seconds\n{metric} >= {rule["threshold"]}\n'

def investigation_spl(rule):
    # Group selectors are intentionally explicit placeholders, not dashboard tokens.
    selectors=' '.join(f'{f}="REPLACE_{f.upper()}"' for f in rule['group_by'])
    fields=list(dict.fromkeys(['_time','host','log_type','channel','event_id']+rule['group_by']+rule['investigation_fields']+['_raw']))
    return (f'index=detection_lab log_type="{rule["log_source"]}" {selectors} earliest=-30m@m latest=now\n'
            + '| sort 0 _time\n| table '+' '.join(fields)+'\n')

def artifacts(rules):
    attack=load_attack()
    result={}
    for r in rules:
        card=f'# {r["id"]} {r["title"]}\n\n'
        card+=f'- 状態：{r["status"]} / 重要度：{r["level"]}\n- SIEM：{r["siem"]}\n- 対象ログ：{r["log_source"]}\n\n'
        card+='## MITRE ATT&CK Matrix上の位置\n\n'+position(r,attack)+'\n'+r['attack_rationale']+'\n\n'
        if r.get('previous_attack_ids'):
            card+='旧対応：'+', '.join(r['previous_attack_ids'])+'。現在の位置を公式STIXデータと照合して更新。\n\n'
        card+='[リポジトリ全体のマトリクス](../matrix.md)。これは技法の一部に対する検知仮説で、技法全体のカバレッジではありません。\n\n'
        card+='## 対象ログ・必要フィールド\n\n'
        card+='- 検知に必須：'+', '.join(f'`{f}`' for f in r['required_fields'])+'\n'
        card+='- 調査に推奨：'+', '.join(f'`{f}`' for f in r['investigation_fields'])+'\n\n'
        card+=r['prerequisites']+'\n\n型・元項目・欠損監視は[フィールド定義](../log-sources.md)を参照。推奨項目が未採取の場合は調査結果に制約を記録します。\n\n'
        card+='## 検知条件\n\n`=` は一致、`~=` は正規表現一致、`>=` は以上、`AND` はすべて満たす意味です。`dc()` は異なる値の数です。`~=` は説明・JSON定義の記号で、SPL本文では `match()` に変換します。必須フィールドがNULLなら対象外です。\n\n```text\n'+conditions(r)+'```\n\n'
        card+='## 検知SPL（Splunk）\n\n`index=detection_lab` を正規化済みログのindexに変更してください。5分間隔、5分遅延の検索を想定しています。生ログにそのまま適用せず[Splunk導入手順](../deployment.md)でフィールドを確認してください。\n\n```spl\n'+spl(r)+'```\n\n'
        card+='## 誤検知とチューニング\n\n'+r['false_positives']+'\n\n'
        card+='## 調査手順・判断基準\n\n'+'\n\n'.join(f'{i+1}. {s}' for i,s in enumerate(r['triage']))+'\n\n'
        card+='### 調査SPL：元イベントの時系列\n\n`REPLACE_...` を検知結果の集約キーに置換します。過去アラートでは `earliest` / `latest` を発生時刻の前後15分の絶対時刻（Unix秒）に変更してください。下記の直近30分は調査開始例です。別ログ種別との照合は対象indexとlog_typeを切り替え、端末IP・host・ユーザーの対応を確認して行います。\n\n```spl\n'+investigation_spl(r)+'```\n\n'
        card+='推奨フィールドが未抽出なら `_raw` を参照します。調査SPLは検知条件を再適用せず、同じキーの正常・異常両方を表示します。キー以外の宛先・利用者へ展開する場合は該当セレクタを外して範囲を広げます。\n\n'
        card+='## 限界・見逃す条件\n\n'+'\n\n'.join('- '+s for s in r['limitations'])+'\n\n'
        card+='共通制約：固定5分窓をまたぐ閾値未満の分散、5分を超える収集遅延、必須フィールド欠損、重複転送の影響を評価してください。Splunk上の実ログ検証・PCRE評価は未実施で、合成テストの成功は本番検知率を示しません。\n\n'
        card+='## 参考文献\n\n'
        card+='\n\n'.join(f'- [{ref["title"]}]({ref["url"]})\n  - 概要・利用箇所：{ref["summary"]}\n  - 確認日：{ref["accessed"]}' for ref in r['references'])+'\n'
        result[f'docs/rules/{r["id"]}.md']=card

    matrix='# MITRE ATT&CK Enterprise Matrixとルールの位置\n\n'
    matrix+='公式の戦術列順で掲載し、横幅を抑えるため前半・後半に分けています。各セルの親技法→サブ技法がルールの位置です。未実装の技法一覧そのものは[公式Matrix](https://attack.mitre.org/matrices/enterprise/)を参照してください。\n\n'
    matrix+='**主**＝本ルールの主な検知仮説、**関連**＝公式の所属戦術だが本ルールでは実行・権限昇格等の成立まで判定しない位置。未実装＝このリポジトリに対応ルールなし。全て候補カバレッジです。\n\n'
    matrix+=f'基準：2026-09-09に取得した[MITRE公式STIX]({attack["source"]})、commit `{attack["commit"]}`。旧Defense Evasionの分類を固定利用せず、このスナップショットのStealth / Defense Impairmentを用います。\n\n'
    for start,end in [(0,8),(8,len(attack['tactics']))]:
        ts=attack['tactics'][start:end]
        matrix+=f'## 戦術列 {start+1}〜{end}\n\n|'+ '|'.join(link(t) for t in ts)+'|\n|'+ '|'.join('---' for _ in ts)+'|\n'
        cols=[]
        for t in ts:
            cells=[]
            for r in rules:
                if t['slug'] not in r['attack_tactics']: continue
                tech=attack['techniques'][r['attack_id']]
                parent=attack['techniques'][r['attack_id'].split('.')[0]]
                cell=link(parent)
                if '.' in r['attack_id']: cell+=' → '+link(tech)
                cell+=f'<br>[{r["id"]}](rules/{r["id"]}.md) / '+('主' if t['slug']==r['tactic'] else '関連')
                cells.append(cell)
            cols.append(cells or ['未実装'])
        for row in range(max(map(len,cols))):
            matrix+='|'+'|'.join(col[row] if row<len(col) else ' ' for col in cols)+'|\n'
        matrix+='\n'
    matrix+='## 技法 × 対象ログ\n\n|親技法 → サブ技法|Windows Event|FW|Proxy|NDR|\n|---|---|---|---|---|\n'
    for tech_id in sorted({r['attack_id'] for r in rules}):
        tech=attack['techniques'][tech_id]
        parent=attack['techniques'][tech_id.split('.')[0]]
        title=link(parent)+(' → '+link(tech) if '.' in tech_id else '')
        cells=[' / '.join(f'[{r["id"]}](rules/{r["id"]}.md)' for r in rules if r['attack_id']==tech_id and r['log_source']==s) or '—' for s in ['windows','fw','proxy','ndr']]
        matrix+='|'+title+'|'+'|'.join(cells)+'|\n'
    matrix+='\nWIN-002は旧T1070.001からT1685.005へ更新。WIN-004は親T1098からT1098.007へ詳細化。IDの更新で検知件数を増やした扱いにはしません。\n'
    result['docs/matrix.md']=matrix
    return result

if __name__=='__main__':
    rules=load_rules()
    for path, content in artifacts(rules).items():
        p=ROOT/path
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(content,encoding='utf-8')
    print(f'Generated artifacts for {len(rules)} rules')
