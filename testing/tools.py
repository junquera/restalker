def _get_text(file: str) -> str:
    text = None
    with open(file, 'r', encoding='utf-8') as f:
        text = f.read()
        f.close()
    return text


def _get_expectations(file: str) -> list[str]:
    import json
    text = None

    with open(file, 'r', encoding='utf-8') as f:
        text = json.load(f)
        f.close()
    return text


def get_data(current_dir: str, name: str) -> tuple[str, list[str]]:
    return (_get_text(f'{current_dir}{name}.txt'), _get_expectations(f'{current_dir}{name}.json'))


def restalker_to_array(results) -> list[str]:
    ret = set()
    rr = []
    import re

    for r in results:
        r_str = str(r)
        normalized = re.sub(r'^\w+\((.*)\)$', r'\1', r_str)
        ret.add(normalized)

    for r in ret:
        rr.append(r)
    return rr


def compare_lists(results: list[str], expectations: list[str]) -> dict:
    results_set = set(results)
    expectations_set = set(expectations)
    missing = list(expectations_set - results_set)
    extra = list(results_set - expectations_set)
    return {
        "missing": missing,
        "extra": extra
    }
