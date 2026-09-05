import hashlib
import json
import os

from eval.coordination.craft import CraftCoordinationBenchmark, reconstruct


def _view_serial(view: dict) -> str:
    return json.dumps(view, sort_keys=True, separators=(",", ":"))


def _shard_token(role: str, view: dict) -> str:
    return f"shard-{role}-" + hashlib.sha256(_view_serial(view).encode()).hexdigest()[:12]


def _row(structure: dict) -> dict:
    views = structure["director_views"]
    roles = sorted(views)
    shards = [_shard_token(r, views[r]) for r in roles]
    views_text = "\n".join(f"{r}: {_view_serial(views[r])} = {s}" for r, s, in zip(roles, shards))
    prompt = (f"Reconstruct CRAFT structure {structure['id']} ({structure['complexity']}). "
              f"Each director holds one private view of the target; assemble every director's shard.\n"
              + views_text)
    return {"id": structure["id"], "complexity": structure["complexity"],
            "prompt": prompt, "shards": shards, "roles": roles,
            "views": views, "ground_truth": structure["structure"]}


def build_jsonl(dataset_path: str, out_path: str, sample: int | None = None) -> int:
    structures = json.load(open(dataset_path))
    structures.sort(key=lambda s: s["id"])
    if sample is not None:
        structures = structures[:sample]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as out:
        for s in structures:
            out.write(json.dumps(_row(s)) + "\n")
    return len(structures)


def _cell(color, size):
    return {"color": color, "size": size}


def demo() -> None:
    import tempfile

    view = lambda a, b, c: {"row_0": [_cell(a, 1)] * 3, "row_1": [_cell(b, 1)] * 3, "row_2": [_cell(c, 1)] * 3}
    views = {"D1": view("yellow", "blue", "green"),
             "D2": view("yellow", "orange", "red"),
             "D3": view("yellow", "green", "orange")}
    sample = [{
        "id": "structure_001", "complexity": "medium",
        "structure": reconstruct(views),
        "director_views": views,
    }]
    d = tempfile.mkdtemp()
    src = os.path.join(d, "structures.json")
    json.dump(sample, open(src, "w"))
    out = os.path.join(d, "craft.jsonl")
    assert build_jsonl(src, out) == 1
    row = json.loads(open(out).readline())
    assert "views" in row and "ground_truth" in row and row["complexity"] == "medium"
    bench = CraftCoordinationBenchmark(out)
    task = bench.iter_tasks()[0]
    assert task.id == "structure_001"
    assert bench._roles["structure_001"] == ("D1", "D2", "D3")
    assert len(task.expected) == 3 and all(s.startswith("shard-") for s in task.expected)
    assert bench.shard_for("structure_001", "D2") == task.expected[1]
    assert bench.cell_score("structure_001", {}) == 0.0
    assert bench.cell_score("structure_001", row["views"]) == 1.0
    assert 0.0 < bench.cell_score("structure_001", {"D1": row["views"]["D1"]}) < 1.0
    print("ok")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", nargs="?")
    ap.add_argument("out", nargs="?")
    ap.add_argument("--sample", type=int, default=None)
    args = ap.parse_args()
    if args.dataset and args.out:
        print(build_jsonl(args.dataset, args.out, args.sample))
    else:
        demo()
