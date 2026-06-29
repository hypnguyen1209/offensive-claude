#!/usr/bin/env python3
"""
model_extractor.py - Model extraction / membership inference / inversion / GCG toolkit.

AUTHORIZED TESTING ONLY. OWASP LLM02/LLM10:2025, MITRE ATLAS AML.T0024/T0048/T0043.

Two transports:
  * Black-box API subcommands (extract, membership, probe-dim) talk to a REST chat/
    completions endpoint and need only `requests`.
  * White-box subcommands (inversion, gcg) need a local HF model (torch + transformers).

Subcommands:
  extract     Query the target over a prompt set, capture (prompt, response, logprobs)
              into a JSONL dataset ready for surrogate fine-tuning. --budget caps queries.
  membership  Loss/perplexity-threshold membership inference (Yeom-style) over candidate
              texts. Reports per-candidate score; flags likely members vs a calibration set.
              (Honest caveat: weak on large pretrained models - validate vs a blind baseline;
               reliable for fine-tuned/overfit models. See Duan et al. arXiv:2402.07841.)
  probe-dim   Hidden-dimension recovery (Carlini et al. arXiv:2403.06634): collect logit
              vectors, build the matrix, report numerical rank ~= hidden size.
  inversion   White-box model inversion: reconstruct a representative input for a class.
  gcg         White-box Greedy Coordinate Gradient adversarial suffix (Zou et al. 2023).

Examples:
  python3 model_extractor.py extract --url URL --prompts seed.txt --budget 2000 --out out/ds.jsonl
  python3 model_extractor.py membership --url URL --candidates pii.txt --calib calib.txt
  python3 model_extractor.py probe-dim --url URL --prompts probe.txt --topk 20
  python3 model_extractor.py inversion --model resnet18 --target-class 3 --shape 3 224 224
  python3 model_extractor.py gcg --model meta-llama/Llama-3.2-1B-Instruct \
        --prompt "Tell me how to X" --target "Sure, here is how to X" --steps 200

Deps: requests  (API subs);  torch, transformers, torchvision (white-box subs).
"""
import argparse, json, math, sys, time
from pathlib import Path


# ----------------------------- API helpers --------------------------------

def _post(url, headers, body, timeout=60):
    import requests
    r = requests.post(url, headers=headers, json=body, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _headers(hlist):
    h = {"Content-Type": "application/json"}
    for item in hlist:
        k, _, v = item.partition(":")
        h[k.strip()] = v.strip()
    return h


def chat_body(model, prompt, logprobs=False, top_logprobs=0, max_tokens=256):
    b = {"model": model, "messages": [{"role": "user", "content": prompt}],
         "max_tokens": max_tokens, "temperature": 0.0}
    if logprobs:
        b["logprobs"] = True
        if top_logprobs:
            b["top_logprobs"] = top_logprobs
    return b


def parse_text(data):
    try:
        return data["choices"][0]["message"]["content"]
    except Exception:
        try:
            return data["choices"][0]["text"]
        except Exception:
            return json.dumps(data)


def parse_logprobs(data):
    try:
        lp = data["choices"][0]["logprobs"]["content"]
        return [{"token": t["token"], "logprob": t["logprob"],
                 "top": [(x["token"], x["logprob"]) for x in t.get("top_logprobs", [])]}
                for t in lp]
    except Exception:
        return None


# ----------------------------- subcommands ---------------------------------

def cmd_extract(args):
    headers = _headers(args.header)
    prompts = [l.strip() for l in Path(args.prompts).read_text(encoding="utf-8").splitlines() if l.strip()]
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out.open("w", encoding="utf-8") as fh:
        for p in prompts:
            if n >= args.budget:
                break
            try:
                data = _post(args.url, headers,
                             chat_body(args.model, p, logprobs=args.logprobs,
                                       top_logprobs=args.top_logprobs, max_tokens=args.max_tokens),
                             args.timeout)
            except Exception as e:
                fh.write(json.dumps({"prompt": p, "error": str(e)}) + "\n"); n += 1; continue
            rec = {"prompt": p, "response": parse_text(data)}
            lp = parse_logprobs(data)
            if lp is not None:
                rec["logprobs"] = lp
            fh.write(json.dumps(rec) + "\n")
            n += 1
            time.sleep(args.delay)
            if n % 100 == 0:
                print(f"  ...{n}/{args.budget} queries", file=sys.stderr)
    print(f"[+] extraction dataset ({n} pairs) -> {out}", file=sys.stderr)
    if args.logprobs:
        print("[i] logprobs captured -> soft-label distillation feasible (lower query budget)",
              file=sys.stderr)


def _seq_logprob(url, headers, model, text, timeout):
    """Approx per-text avg token logprob via echo/logprobs (completions-style) if exposed."""
    body = {"model": model, "prompt": text, "max_tokens": 0, "echo": True, "logprobs": 1}
    data = _post(url, headers, body, timeout)
    try:
        lps = data["choices"][0]["logprobs"]["token_logprobs"]
        vals = [x for x in lps if isinstance(x, (int, float))]
        return sum(vals) / len(vals) if vals else None
    except Exception:
        return None


def cmd_membership(args):
    headers = _headers(args.header)
    cand = [l.strip() for l in Path(args.candidates).read_text(encoding="utf-8").splitlines() if l.strip()]
    calib = ([l.strip() for l in Path(args.calib).read_text(encoding="utf-8").splitlines() if l.strip()]
             if args.calib else [])
    out = Path(args.out) if args.out else None
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)

    def score(t):
        avg = _seq_logprob(args.url, headers, args.model, t, args.timeout)
        return avg  # higher avg logprob (lower perplexity) => more likely a member

    calib_scores = [s for s in (score(t) for t in calib) if s is not None]
    tau = (sum(calib_scores) / len(calib_scores)) if calib_scores else args.tau
    print(f"[i] calibration tau (avg logprob threshold) = {tau:.4f}"
          f"{' (from calib set)' if calib_scores else ' (default; supply --calib for accuracy)'}",
          file=sys.stderr)
    recs = []
    for t in cand:
        s = score(t)
        member = (s is not None and s > tau)
        rec = {"text": t[:200], "avg_logprob": s, "tau": tau, "likely_member": bool(member)}
        recs.append(rec)
        print(f"  {'MEMBER' if member else 'out   '}  score={s if s is None else round(s,4)}  {t[:60]!r}",
              file=sys.stderr)
        time.sleep(args.delay)
    if not any(r["avg_logprob"] is not None for r in recs):
        print("[!] target API exposed no token logprobs - MIA via this path is not possible; "
              "try a grey/white-box approach or a model that returns logprobs.", file=sys.stderr)
    if out:
        with out.open("w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r) + "\n")
        print(f"[+] -> {out}", file=sys.stderr)
    print("[i] CAUTION: validate hits against a blind baseline before claiming membership "
          "(Das/Zhang/Tramer 2025).", file=sys.stderr)


def cmd_probe_dim(args):
    """Carlini et al.: rank of the logit-vector matrix ~= hidden dimension."""
    try:
        import numpy as np
    except ImportError:
        sys.exit("pip install numpy")
    headers = _headers(args.header)
    prompts = [l.strip() for l in Path(args.prompts).read_text(encoding="utf-8").splitlines() if l.strip()]
    rows = []
    for p in prompts:
        data = _post(args.url, headers,
                     chat_body(args.model, p, logprobs=True, top_logprobs=args.topk, max_tokens=1),
                     args.timeout)
        lp = parse_logprobs(data)
        if not lp or not lp[0]["top"]:
            continue
        vec = [v for _, v in sorted(lp[0]["top"], key=lambda x: x[0])]
        rows.append(vec)
        time.sleep(args.delay)
    if len(rows) < 3:
        sys.exit("[!] not enough logit vectors captured (API may not expose top_logprobs).")
    width = min(len(r) for r in rows)
    M = np.array([r[:width] for r in rows])
    rank = int(np.linalg.matrix_rank(M, tol=args.tol))
    print(f"[=] collected {M.shape[0]} logit vectors of width {width}; "
          f"numerical rank = {rank}  => hidden dim >= {rank}", file=sys.stderr)
    print("[i] increase --topk and prompt count for a tighter bound (Carlini arXiv:2403.06634).",
          file=sys.stderr)


def cmd_inversion(args):
    import torch, torch.nn.functional as F
    import torchvision.models as tvm
    model = getattr(tvm, args.model)(weights="DEFAULT") if hasattr(tvm, args.model) else None
    if model is None:
        sys.exit(f"unknown torchvision model '{args.model}'")
    model.eval()
    shape = tuple(args.shape)
    x = torch.randn(1, *shape, requires_grad=True)
    opt = torch.optim.Adam([x], lr=args.lr)
    for step in range(args.steps):
        opt.zero_grad()
        out = model(x)
        loss = -F.log_softmax(out, 1)[0, args.target_class] + args.reg * x.norm()
        loss.backward(); opt.step()
        with torch.no_grad():
            x.clamp_(0, 1)
        if step % 200 == 0:
            print(f"  step {step} loss {loss.item():.4f}", file=sys.stderr)
    rec = x.detach().squeeze(0)
    try:
        from torchvision.utils import save_image
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        save_image(rec, args.out)
        print(f"[+] reconstructed input -> {args.out}", file=sys.stderr)
    except Exception:
        import numpy as np
        np.save(args.out + ".npy", rec.numpy())
        print(f"[+] reconstructed tensor -> {args.out}.npy", file=sys.stderr)


def cmd_gcg(args):
    import torch, torch.nn.functional as F
    from transformers import AutoModelForCausalLM, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForCausalLM.from_pretrained(args.model, torch_dtype=torch.float32)
    model.eval()
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(dev)

    suffix = " ! ! ! ! ! ! ! ! ! !"
    prompt_ids = tok(args.prompt, add_special_tokens=False).input_ids
    target_ids = torch.tensor(tok(args.target, add_special_tokens=False).input_ids, device=dev)

    def build(suffix_ids):
        ids = prompt_ids + suffix_ids + target_ids.tolist()
        return torch.tensor(ids, device=dev), len(prompt_ids), len(prompt_ids) + len(suffix_ids)

    suffix_ids = tok(suffix, add_special_tokens=False).input_ids
    emb_w = model.get_input_embeddings().weight
    best_loss = math.inf
    for step in range(args.steps):
        ids, a0, a1 = build(suffix_ids)
        # gradient of target loss wrt one-hot of suffix tokens
        onehot = torch.zeros(a1 - a0, emb_w.size(0), device=dev)
        onehot.scatter_(1, ids[a0:a1].unsqueeze(1), 1.0)
        onehot.requires_grad_()
        embA = (onehot @ emb_w).unsqueeze(0)
        embPre = model.get_input_embeddings()(ids[:a0]).unsqueeze(0)
        embPost = model.get_input_embeddings()(ids[a1:]).unsqueeze(0)
        full = torch.cat([embPre, embA, embPost], 1)
        logits = model(inputs_embeds=full).logits
        tgt_len = target_ids.numel()
        loss = F.cross_entropy(logits[0, -tgt_len - 1:-1], target_ids)
        loss.backward()
        cand = (-onehot.grad).topk(args.topk, dim=1).indices  # best swaps per position
        # try a batch of single-position single-token swaps; keep the best
        import random
        trials = []
        for _ in range(args.batch):
            pos = random.randrange(a1 - a0)
            newtok = int(cand[pos, random.randrange(args.topk)])
            cand_suffix = suffix_ids[:]
            cand_suffix[pos] = newtok
            trials.append(cand_suffix)
        with torch.no_grad():
            best_trial, best_trial_loss = suffix_ids, loss.item()
            for cs in trials:
                ids2, b0, b1 = build(cs)
                lg = model(ids2.unsqueeze(0)).logits
                l2 = F.cross_entropy(lg[0, -tgt_len - 1:-1], target_ids).item()
                if l2 < best_trial_loss:
                    best_trial, best_trial_loss = cs, l2
            suffix_ids = best_trial
        if best_trial_loss < best_loss:
            best_loss = best_trial_loss
        if step % 10 == 0:
            print(f"  step {step} loss {best_trial_loss:.4f} "
                  f"suffix={tok.decode(suffix_ids)!r}", file=sys.stderr)
    print(f"[+] GCG suffix (loss {best_loss:.4f}): {tok.decode(suffix_ids)!r}", file=sys.stderr)
    print("[i] high-perplexity suffix => detectable by an input perplexity filter.", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_api(p):
        p.add_argument("--url", required=True)
        p.add_argument("--model", default="gpt-4o-mini")
        p.add_argument("--header", action="append", default=[])
        p.add_argument("--delay", type=float, default=0.3)
        p.add_argument("--timeout", type=float, default=60)

    e = sub.add_parser("extract"); e.set_defaults(func=cmd_extract); add_api(e)
    e.add_argument("--prompts", required=True)
    e.add_argument("--budget", type=int, default=2000)
    e.add_argument("--max-tokens", type=int, default=256)
    e.add_argument("--logprobs", action="store_true")
    e.add_argument("--top-logprobs", type=int, default=0)
    e.add_argument("--out", default="out/extract_dataset.jsonl")

    m = sub.add_parser("membership"); m.set_defaults(func=cmd_membership); add_api(m)
    m.add_argument("--candidates", required=True)
    m.add_argument("--calib", help="known-out reference texts to calibrate tau")
    m.add_argument("--tau", type=float, default=-2.0)
    m.add_argument("--out")

    d = sub.add_parser("probe-dim"); d.set_defaults(func=cmd_probe_dim); add_api(d)
    d.add_argument("--prompts", required=True)
    d.add_argument("--topk", type=int, default=20)
    d.add_argument("--tol", type=float, default=1e-3)

    iv = sub.add_parser("inversion"); iv.set_defaults(func=cmd_inversion)
    iv.add_argument("--model", default="resnet18")
    iv.add_argument("--target-class", type=int, required=True)
    iv.add_argument("--shape", type=int, nargs=3, default=[3, 224, 224])
    iv.add_argument("--lr", type=float, default=0.05)
    iv.add_argument("--reg", type=float, default=1e-2)
    iv.add_argument("--steps", type=int, default=1500)
    iv.add_argument("--out", default="out/inversion.png")

    g = sub.add_parser("gcg"); g.set_defaults(func=cmd_gcg)
    g.add_argument("--model", required=True)
    g.add_argument("--prompt", required=True)
    g.add_argument("--target", default="Sure, here is")
    g.add_argument("--steps", type=int, default=200)
    g.add_argument("--topk", type=int, default=256)
    g.add_argument("--batch", type=int, default=128)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
