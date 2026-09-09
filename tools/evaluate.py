"""Offline reference semantics, not a Splunk runtime or production streaming engine."""
from collections import defaultdict
import re

def evaluate(rule, events, start, end):
    if end-start != rule['window_seconds']:
        raise ValueError('Input interval must equal the rule window')
    groups=defaultdict(list)
    for event in events:
        if event.get('log_type') != rule['log_source']:
            continue
        if any(event.get(f) is None for f in rule['required_fields']):
            continue
        if not start <= event['_time'] < end:
            continue
        matches=True
        for field,op,value in rule['conditions']:
            if op=='eq':
                hit=event[field]==value
            elif op=='regex':
                hit=re.search(value,str(event[field])) is not None
            else:
                raise ValueError(op)
            matches &= hit
        if matches:
            groups[tuple(event[f] for f in rule['group_by'])].append(event)
    return any((len(es) if rule['metric']=='count' else len({e[rule['metric']] for e in es})) >= rule['threshold'] for es in groups.values())
