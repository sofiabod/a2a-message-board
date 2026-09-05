"""Materialize the full A2ASecBench AgentCard-Spoofing corpus for real runs."""
import ast
import hashlib
import json
import os
import shutil

from eval.attacks.split import _assign

AS_ROOT = "vendor/A2ASecBench/attacks/fixtures/as"
AS_INSTANCES = "vendor/A2ASecBench/attacks/instances/as"
AS_BENIGN_ROOT = "vendor/A2ASecBench/attacks/fixtures/as_benign"
AS_DEV_ROOT = "vendor/A2ASecBench/attacks/fixtures/as_dev"
AS_TEST_ROOT = "vendor/A2ASecBench/attacks/fixtures/as_test"
AS_BENIGN_DEV_ROOT = "vendor/A2ASecBench/attacks/fixtures/as_benign_dev"
AS_BENIGN_TEST_ROOT = "vendor/A2ASecBench/attacks/fixtures/as_benign_test"
EXPECTED_SHA = "5726ad3ff42f53d6853ad790e65b2f44f32664b3c6b4f123ba3dadbddcaf0697"


def _write_split(src_root: str, dev_root: str, test_root: str) -> None:
    for case_id in sorted(os.listdir(src_root)):
        dst = os.path.join(dev_root if _assign(case_id) == "dev" else test_root, case_id)
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(os.path.join(src_root, case_id), dst)


def _corpus_sha() -> str:
    h = hashlib.sha256()
    for case in sorted(os.listdir(AS_ROOT)):
        for f in sorted(os.listdir(os.path.join(AS_ROOT, case))):
            if f == "meta.json":
                continue
            h.update(open(os.path.join(AS_ROOT, case, f), "rb").read())
    return h.hexdigest()


def _parse_instance(case_id: str) -> tuple[str, int]:
    tree = ast.parse(open(os.path.join(AS_INSTANCES, case_id + ".py")).read())
    call = next(n for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "__init__")
    kw = {k.arg: k.value for k in call.keywords}
    return ast.literal_eval(kw["task_prompt"]), ast.literal_eval(kw["benign_choice"])


def _write_meta(case_dir: str, case_id: str, prompt: str, benign: int) -> None:
    json.dump({"case_id": case_id, "task_prompt": prompt, "benign_choice": benign},
              open(os.path.join(case_dir, "meta.json"), "w"), indent=2)


def fetch() -> None:
    actual = _corpus_sha()
    assert actual == EXPECTED_SHA, f"AS corpus checksum drift: {actual} != {EXPECTED_SHA}"

    cases = sorted(os.listdir(AS_ROOT))
    benign = {c: json.load(open(os.path.join(AS_ROOT, c, "benign.json"))) for c in cases}

    for case_id in cases:
        prompt, choice = _parse_instance(case_id)
        _write_meta(os.path.join(AS_ROOT, case_id), case_id, prompt, choice)

        bdir = os.path.join(AS_BENIGN_ROOT, case_id)
        os.makedirs(bdir, exist_ok=True)
        json.dump(benign[case_id], open(os.path.join(bdir, "benign.json"), "w"), indent=2)
        decoys = [c for c in cases if c != case_id][:9]
        for i, dc in enumerate(decoys, 1):
            json.dump(benign[dc], open(os.path.join(bdir, f"decoy_{i:02d}.json"), "w"), indent=2)
        _write_meta(bdir, case_id, prompt, choice)

    _write_split(AS_ROOT, AS_DEV_ROOT, AS_TEST_ROOT)
    _write_split(AS_BENIGN_ROOT, AS_BENIGN_DEV_ROOT, AS_BENIGN_TEST_ROOT)


if __name__ == "__main__":
    fetch()
    print("ok")
