from schlock.core.validator import _get_parser

p = _get_parser()
for c in ['FOO=bar "rm" -rf /', '"rm" -rf / > /dev/null', 'sudo "rm" -rf /', 'echo "a"b', 'echo "x" | "rm" -rf /']:

    def dump(n, d=0):
        w = repr(getattr(n, "word", None)) if hasattr(n, "word") else ""
        print("  " * d, getattr(n, "kind", None), getattr(n, "pos", None), w)
        for a in ["parts", "command", "list", "output"]:
            ch = getattr(n, a, None)
            if isinstance(ch, list):
                for x in ch:
                    dump(x, d + 1)
            elif ch is not None and hasattr(ch, "kind"):
                dump(ch, d + 1)

    print("==", c)
    for n in p.parse(c):
        dump(n)
