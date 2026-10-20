"""Evaluate control evidence freshness and artifact integrity without certifying compliance."""
import argparse
from datetime import date
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys


def artifact(root, name):
    logical = PurePosixPath(name)
    if not name or '\\' in name or ':' in name or logical.is_absolute() or '..' in logical.parts or str(logical) != name:
        raise ValueError(f'Unsafe artifact path: {name}')
    root = Path(root).resolve(strict=True)
    path = root.joinpath(*logical.parts)
    for part in (path, *path.parents):
        if part == root:
            break
        if part.is_symlink() or getattr(part, 'is_junction', lambda: False)():
            raise ValueError('Linked artifacts are forbidden')
    if not path.resolve().is_relative_to(root):
        raise ValueError('Artifact escapes evidence root')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            digest.update(chunk)
    return digest.hexdigest()


def evaluate(register, root, as_of):
    if register.get('schema') != 'audit-evidence/v1':
        raise ValueError('Unsupported register schema')
    controls = register['controls']
    if not isinstance(controls, list) or not controls:
        raise ValueError('A nonempty control list is required')
    seen = set()
    report = []
    for control in controls:
        identifier = control['id']
        if not isinstance(identifier, str) or not identifier or identifier in seen:
            raise ValueError('Control IDs must be unique nonempty strings')
        seen.add(identifier)
        if type(control['applicable']) is not bool:
            raise ValueError('applicable must be a boolean')
        if type(control['max_age_days']) is not int or control['max_age_days'] < 0:
            raise ValueError('max_age_days must be a nonnegative integer')
        issues = []
        if not control.get('owner'):
            issues.append('missing_owner')
        evidence = control.get('evidence', [])
        if not isinstance(evidence, list):
            raise ValueError('evidence must be a list')
        if not control['applicable']:
            if not control.get('exclusion_reason'):
                issues.append('unjustified_exclusion')
            status = 'gap' if issues else 'excluded'
        else:
            if not evidence:
                issues.append('missing_evidence')
            evidence_paths = set()
            for entry in evidence:
                name = entry['path']
                if name in evidence_paths:
                    raise ValueError(f'Duplicate evidence path for {identifier}')
                evidence_paths.add(name)
                expected = entry['sha256']
                if not isinstance(expected, str) or len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
                    raise ValueError(f'Invalid digest for {identifier}')
                age = (as_of - date.fromisoformat(entry['collected_on'])).days
                if age < 0:
                    issues.append(f'future_evidence:{name}')
                elif age > control['max_age_days']:
                    issues.append(f'stale_evidence:{name}')
                try:
                    actual = artifact(root, name)
                except FileNotFoundError:
                    issues.append(f'missing_artifact:{name}')
                else:
                    if actual != expected:
                        issues.append(f'hash_mismatch:{name}')
            # "ready" means ready for auditor review, never effectiveness/compliance.
            status = 'gap' if issues else 'ready_for_review'
        report.append({'id': identifier, 'owner': control.get('owner'), 'status': status, 'issues': issues})
    counts = {status: sum(row['status'] == status for row in report) for status in ('gap', 'excluded', 'ready_for_review')}
    return {'as_of': as_of.isoformat(), 'summary': counts, 'controls': report}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('register', type=Path)
    parser.add_argument('--evidence-root', required=True, type=Path)
    parser.add_argument('--as-of', required=True, type=date.fromisoformat)
    args = parser.parse_args(argv)
    try:
        report = evaluate(json.loads(args.register.read_text(encoding='utf-8')), args.evidence_root, args.as_of)
        print(json.dumps(report, indent=2))
        return int(report['summary']['gap'] > 0)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
