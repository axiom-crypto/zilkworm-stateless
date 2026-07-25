// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

/* OpenVM pairing-protocol port (see openvm_pairing.hpp).
 *
 * Faithful C++ port of openvm-org/openvm@develop-v2.1.0
 * guest-libs/pairing/src/{bn254,bls12_381} and
 * extensions/pairing/guest/src/pairing/{miller_loop,miller_step}.rs:
 *   - Fp2 arithmetic: OpenVM complex-extension custom instructions
 *   - Fp6/Fp12 tower: software over Fp2 (sextic w-basis, w^6 = xi;
 *     Fp12.c[i] = w^i coefficient, matching the Rust SexticExtField layout
 *     and the HintFinalExp hint stream layout)
 *   - Miller loops: software with the curve-specific pseudo-binary
 *     encodings, D-type (013) lines for bn254, M-type (023) for bls12-381
 *   - Final exponentiation: HintFinalExp residue witness (c, u/s) verified
 *     per Theorem 3 of eprint 2024/640 (bn254) / the gnark condition
 *     (bls12-381), with a square-and-multiply f^FINAL_EXPONENT fallback.
 */

#include "include/openvm_pairing.hpp"

#include "include/openvm_ecc.hpp"
#include "include/openvm_pairing_constants.hpp"
#include "include/openvm_syscalls.hpp"

#include <cstring>

namespace opc = openvm_pairing_consts;

namespace {

/* ─────────────────────── generic Fp2 / Fp12 machinery ─────────────────── */

// Curve configs: NB = base-field byte length; fp/fp2 ops bind the intrinsic
// wrappers; PAIRING_IDX is the fixed openvm PairingCurve discriminant.
struct BnCfg {
    static constexpr size_t NB = 32;
    static constexpr int PAIRING_IDX = 0;
    static void fadd(void* d, const void* a, const void* b) { openvm::bn254_fp_addmod(d, a, b); }
    static void fsub(void* d, const void* a, const void* b) { openvm::bn254_fp_submod(d, a, b); }
    static void fmul(void* d, const void* a, const void* b) { openvm::bn254_fp_mulmod(d, a, b); }
    static void fdiv(void* d, const void* a, const void* b) { openvm::bn254_fp_divmod(d, a, b); }
    static void f2add(void* d, const void* a, const void* b) { openvm::bn254_fp2_addmod(d, a, b); }
    static void f2sub(void* d, const void* a, const void* b) { openvm::bn254_fp2_submod(d, a, b); }
    static void f2mul(void* d, const void* a, const void* b) { openvm::bn254_fp2_mulmod(d, a, b); }
    static void f2div(void* d, const void* a, const void* b) { openvm::bn254_fp2_divmod(d, a, b); }
};
struct BlsCfg {
    static constexpr size_t NB = 48;
    static constexpr int PAIRING_IDX = 1;
    static void fadd(void* d, const void* a, const void* b) { openvm::bls_fp_addmod(d, a, b); }
    static void fsub(void* d, const void* a, const void* b) { openvm::bls_fp_submod(d, a, b); }
    static void fmul(void* d, const void* a, const void* b) { openvm::bls_fp_mulmod(d, a, b); }
    static void fdiv(void* d, const void* a, const void* b) { openvm::bls_fp_divmod(d, a, b); }
    static void f2add(void* d, const void* a, const void* b) { openvm::bls_fp2_addmod(d, a, b); }
    static void f2sub(void* d, const void* a, const void* b) { openvm::bls_fp2_submod(d, a, b); }
    static void f2mul(void* d, const void* a, const void* b) { openvm::bls_fp2_mulmod(d, a, b); }
    static void f2div(void* d, const void* a, const void* b) { openvm::bls_fp2_divmod(d, a, b); }
};

template <class C>
struct Fp {
    alignas(8) uint8_t b[C::NB];
    static Fp zero() { Fp r; std::memset(r.b, 0, C::NB); return r; }
    static Fp one() { Fp r = zero(); r.b[0] = 1; return r; }
    bool is_zero() const {
        uint8_t acc = 0;
        for (size_t i = 0; i < C::NB; ++i) acc |= b[i];
        return acc == 0;
    }
    bool eq(const Fp& o) const { return std::memcmp(b, o.b, C::NB) == 0; }
};

template <class C>
struct Fp2 {
    alignas(8) uint8_t b[2 * C::NB];  // c0 || c1
    static Fp2 zero() { Fp2 r; std::memset(r.b, 0, sizeof(r.b)); return r; }
    static Fp2 one() { Fp2 r = zero(); r.b[0] = 1; return r; }
    bool is_zero() const {
        uint8_t acc = 0;
        for (size_t i = 0; i < 2 * C::NB; ++i) acc |= b[i];
        return acc == 0;
    }
    bool eq(const Fp2& o) const { return std::memcmp(b, o.b, sizeof(b)) == 0; }

    friend Fp2 operator+(const Fp2& a, const Fp2& b_) { Fp2 r; C::f2add(r.b, a.b, b_.b); return r; }
    friend Fp2 operator-(const Fp2& a, const Fp2& b_) { Fp2 r; C::f2sub(r.b, a.b, b_.b); return r; }
    friend Fp2 operator*(const Fp2& a, const Fp2& b_) { Fp2 r; C::f2mul(r.b, a.b, b_.b); return r; }
    Fp2 neg() const { Fp2 r; const Fp2 z = zero(); C::f2sub(r.b, z.b, this->b); return r; }
    // (c0, c1) -> (c0, -c1)
    Fp2 conjugate() const {
        Fp2 r = *this;
        const Fp<C> z = Fp<C>::zero();
        C::fsub(r.b + C::NB, z.b, this->b + C::NB);
        return r;
    }
    // Multiply both coefficients by a base-field scalar.
    Fp2 mul_base(const Fp<C>& s) const {
        Fp2 r;
        C::fmul(r.b, this->b, s.b);
        C::fmul(r.b + C::NB, this->b + C::NB, s.b);
        return r;
    }
    // dst = a / b (b invertible; used for Miller-step lambdas).
    friend Fp2 fp2_div(const Fp2& a, const Fp2& b_) { Fp2 r; C::f2div(r.b, a.b, b_.b); return r; }
};

// XI constants: bn254 xi = 9 + u, bls12-381 xi = 1 + u.
template <class C> Fp2<C> xi_const();
template <> Fp2<BnCfg> xi_const<BnCfg>() {
    Fp2<BnCfg> x = Fp2<BnCfg>::zero();
    x.b[0] = 9;
    x.b[BnCfg::NB] = 1;
    return x;
}
template <> Fp2<BlsCfg> xi_const<BlsCfg>() {
    Fp2<BlsCfg> x = Fp2<BlsCfg>::zero();
    x.b[0] = 1;
    x.b[BlsCfg::NB] = 1;
    return x;
}

// Fp12 in the sextic w-basis: c[i] is the coefficient of w^i.
template <class C>
struct Fp12 {
    Fp2<C> c[6];
    static Fp12 zero() { Fp12 r; for (auto& x : r.c) x = Fp2<C>::zero(); return r; }
    static Fp12 one() { Fp12 r = zero(); r.c[0] = Fp2<C>::one(); return r; }
    bool is_zero() const {
        for (const auto& x : c)
            if (!x.is_zero()) return false;
        return true;
    }
    bool eq(const Fp12& o) const {
        for (int i = 0; i < 6; ++i)
            if (!c[i].eq(o.c[i])) return false;
        return true;
    }
    // (odd coefficients negated) == Fp12 conjugation over Fp6.
    Fp12 conjugate() const {
        Fp12 r = *this;
        r.c[1] = c[1].neg();
        r.c[3] = c[3].neg();
        r.c[5] = c[5].neg();
        return r;
    }
};

// Hand-derived sextic tower multiplication (operations/sextic_ext_field.rs).
template <class C>
Fp12<C> fp12_mul(const Fp12<C>& l, const Fp12<C>& r) {
    const Fp2<C> xi = xi_const<C>();
    const Fp2<C>* s = l.c;
    const Fp2<C>* o = r.c;
    Fp12<C> out;
    out.c[0] = s[0] * o[0] + xi * (s[1] * o[5] + s[2] * o[4] + s[3] * o[3] + s[4] * o[2] + s[5] * o[1]);
    out.c[1] = s[0] * o[1] + s[1] * o[0] + xi * (s[2] * o[5] + s[3] * o[4] + s[4] * o[3] + s[5] * o[2]);
    out.c[2] = s[0] * o[2] + s[1] * o[1] + s[2] * o[0] + xi * (s[3] * o[5] + s[4] * o[4] + s[5] * o[3]);
    out.c[3] = s[0] * o[3] + s[1] * o[2] + s[2] * o[1] + s[3] * o[0] + xi * (s[4] * o[5] + s[5] * o[4]);
    out.c[4] = s[0] * o[4] + s[1] * o[3] + s[2] * o[2] + s[3] * o[1] + s[4] * o[0] + xi * (s[5] * o[5]);
    out.c[5] = s[0] * o[5] + s[1] * o[4] + s[2] * o[3] + s[3] * o[2] + s[4] * o[1] + s[5] * o[0];
    return out;
}

/* Fp6 helpers over the (even, odd) coefficient split: an Fp12 element is
 * a0 + a1*w with a0 = (c0, c2, c4), a1 = (c1, c3, c5) in the Fp6 basis
 * 1, v, v^2 where v = w^2, v^3 = xi. */
template <class C>
struct Fp6 {
    Fp2<C> c[3];
};

template <class C>
Fp6<C> fp6_mul(const Fp6<C>& a, const Fp6<C>& b, const Fp2<C>& xi) {
    // Schoolbook with v^3 = xi reduction.
    Fp6<C> r;
    r.c[0] = a.c[0] * b.c[0] + xi * (a.c[1] * b.c[2] + a.c[2] * b.c[1]);
    r.c[1] = a.c[0] * b.c[1] + a.c[1] * b.c[0] + xi * (a.c[2] * b.c[2]);
    r.c[2] = a.c[0] * b.c[2] + a.c[1] * b.c[1] + a.c[2] * b.c[0];
    return r;
}

// v * a = (xi*a2, a0, a1)
template <class C>
Fp6<C> fp6_mul_by_v(const Fp6<C>& a, const Fp2<C>& xi) {
    Fp6<C> r;
    r.c[0] = xi * a.c[2];
    r.c[1] = a.c[0];
    r.c[2] = a.c[1];
    return r;
}

template <class C>
Fp6<C> fp6_sub(const Fp6<C>& a, const Fp6<C>& b) {
    Fp6<C> r;
    for (int i = 0; i < 3; ++i) r.c[i] = a.c[i] - b.c[i];
    return r;
}

// Standard Fp6 inversion; the single Fp2 inversion at the end uses the
// native Fp2 Div instruction.
template <class C>
Fp6<C> fp6_inv(const Fp6<C>& a, const Fp2<C>& xi) {
    const Fp2<C>& a0 = a.c[0];
    const Fp2<C>& a1 = a.c[1];
    const Fp2<C>& a2 = a.c[2];
    Fp2<C> t0 = a0 * a0 - xi * (a1 * a2);
    Fp2<C> t1 = xi * (a2 * a2) - a0 * a1;
    Fp2<C> t2 = a1 * a1 - a0 * a2;
    Fp2<C> norm = a0 * t0 + xi * (a2 * t1 + a1 * t2);
    Fp2<C> n_inv = fp2_div(Fp2<C>::one(), norm);
    Fp6<C> r;
    r.c[0] = t0 * n_inv;
    r.c[1] = t1 * n_inv;
    r.c[2] = t2 * n_inv;
    return r;
}

template <class C>
Fp12<C> fp12_inv(const Fp12<C>& x) {
    const Fp2<C> xi = xi_const<C>();
    // Split into a0 + a1*w over Fp6.
    Fp6<C> a0{{x.c[0], x.c[2], x.c[4]}};
    Fp6<C> a1{{x.c[1], x.c[3], x.c[5]}};
    // t = a0^2 - v * a1^2, inverse = (a0 - a1*w) / t
    Fp6<C> t = fp6_sub(fp6_mul(a0, a0, xi), fp6_mul_by_v(fp6_mul(a1, a1, xi), xi));
    Fp6<C> t_inv = fp6_inv(t, xi);
    Fp6<C> r0 = fp6_mul(a0, t_inv, xi);
    Fp6<C> r1 = fp6_mul(a1, t_inv, xi);
    Fp12<C> r;
    r.c[0] = r0.c[0];
    r.c[2] = r0.c[1];
    r.c[4] = r0.c[2];
    r.c[1] = r1.c[0].neg();
    r.c[3] = r1.c[1].neg();
    r.c[5] = r1.c[2].neg();
    return r;
}

// Frobenius map (power 1..3) per guest-libs fp12.rs: for odd powers,
// conjugate each Fp2 coefficient; multiply c[i] (i>=1) by FROB[power][i-1].
template <class C>
Fp12<C> fp12_frobenius(const Fp12<C>& x, int power, const uint8_t* frob_rows[3]) {
    const uint8_t* row = frob_rows[power - 1];
    const size_t fp2b = 2 * C::NB;
    Fp12<C> r;
    if (power & 1) {
        r.c[0] = x.c[0].conjugate();
        for (int i = 1; i < 6; ++i) {
            Fp2<C> coeff;
            std::memcpy(coeff.b, row + (i - 1) * fp2b, fp2b);
            r.c[i] = x.c[i].conjugate() * coeff;
        }
    } else {
        r.c[0] = x.c[0];
        for (int i = 1; i < 6; ++i) {
            Fp2<C> coeff;
            std::memcpy(coeff.b, row + (i - 1) * fp2b, fp2b);
            r.c[i] = x.c[i] * coeff;
        }
    }
    return r;
}

// Square-and-multiply x^exp with a big-endian exponent (exp_bytes, MSB-first).
template <class C>
Fp12<C> fp12_pow_be(const Fp12<C>& x, const uint8_t* exp, size_t exp_len) {
    Fp12<C> acc = Fp12<C>::one();
    bool started = false;
    for (size_t i = 0; i < exp_len; ++i) {
        for (int bit = 7; bit >= 0; --bit) {
            if (started)
                acc = fp12_mul(acc, acc);
            if ((exp[i] >> bit) & 1) {
                if (started)
                    acc = fp12_mul(acc, x);
                else {
                    acc = x;
                    started = true;
                }
            }
        }
    }
    return acc;
}

/* ───────────────────────────── Miller machinery ───────────────────────── */

template <class C>
struct AffP {  // G1 point, canonical LE
    Fp<C> x, y;
    bool is_infinity() const { return x.is_zero() && y.is_zero(); }
};
template <class C>
struct AffP2 {  // G2 point (Fp2 coords)
    Fp2<C> x, y;
    bool is_infinity() const { return x.is_zero() && y.is_zero(); }
    AffP2 neg() const { return {x, y.neg()}; }
};
template <class C>
struct Line {  // UnevaluatedLine/EvaluatedLine share the (b, c) shape
    Fp2<C> b, c;
};

// miller_step.rs formulas (affine, a = 0 curves; lambdas via native Fp2 Div).
template <class C>
void miller_double_step(const AffP2<C>& s, AffP2<C>& out, Line<C>& line) {
    Fp2<C> two_y = s.y + s.y;
    Fp2<C> xx = s.x * s.x;
    Fp2<C> three_xx = xx + xx + xx;
    Fp2<C> lambda = fp2_div(three_xx, two_y);
    Fp2<C> x2 = lambda * lambda - (s.x + s.x);
    Fp2<C> y2 = lambda * (s.x - x2) - s.y;
    out = {x2, y2};
    line.b = lambda.neg();
    line.c = lambda * s.x - s.y;
}

template <class C>
void miller_add_step(const AffP2<C>& s, const AffP2<C>& q, AffP2<C>& out, Line<C>& line) {
    Fp2<C> lambda = fp2_div(s.y - q.y, s.x - q.x);
    Fp2<C> xr = lambda * lambda - s.x - q.x;
    Fp2<C> yr = lambda * (q.x - xr) - q.y;
    out = {xr, yr};
    line.b = lambda.neg();
    line.c = lambda * s.x - s.y;
}

// 2S + Q via (S + Q) + S; returns both chord lines (miller_step.rs).
template <class C>
void miller_double_and_add_step(
    const AffP2<C>& s, const AffP2<C>& q, AffP2<C>& out, Line<C>& l0, Line<C>& l1) {
    // lambda1 = (y_s - y_q) / (x_s - x_q); x_{s+q} = lambda1^2 - x_s - x_q
    Fp2<C> lambda1 = fp2_div(s.y - q.y, s.x - q.x);
    Fp2<C> x_s_plus_q = lambda1 * lambda1 - s.x - q.x;

    // lambda2 = -lambda1 - 2 y_s / (x_{s+q} - x_s)
    Fp2<C> two_y = s.y + s.y;
    Fp2<C> lambda2 = lambda1.neg() - fp2_div(two_y, x_s_plus_q - s.x);
    Fp2<C> x_out = lambda2 * lambda2 - s.x - x_s_plus_q;
    Fp2<C> y_out = lambda2 * (s.x - x_out) - s.y;
    out = {x_out, y_out};

    l0.b = lambda1.neg();
    l0.c = lambda1 * s.x - s.y;
    l1.b = lambda2.neg();
    l1.c = lambda2 * s.x - s.y;
}

// Evaluate an unevaluated line at P via (x/y, 1/y):
// b' = b * (x/y), c' = c * (1/y)  (pairing.rs Evaluatable impls; identical
// formula for both curves).
template <class C>
Line<C> evaluate_line(const Line<C>& l, const Fp<C>& x_over_y, const Fp<C>& y_inv) {
    return {l.b.mul_base(x_over_y), l.c.mul_base(y_inv)};
}

/* line multiplication: D-type (bn254, 013) and M-type (bls, 023) */

template <class C>
Fp12<C> from_line_d(const Line<C>& l) {
    Fp12<C> f = Fp12<C>::zero();
    f.c[0] = Fp2<C>::one();
    f.c[1] = l.b;
    f.c[3] = l.c;
    return f;
}
template <class C>
Fp12<C> from_line_m(const Line<C>& l) {
    Fp12<C> f = Fp12<C>::zero();
    f.c[0] = l.c;
    f.c[2] = l.b;
    f.c[3] = Fp2<C>::one();
    return f;
}

// mul_013_by_013 (bn254/pairing.rs): [x0, x1, x2, x3, x4]
template <class C>
void mul_013_by_013(const Line<C>& l0, const Line<C>& l1, Fp2<C> out[5]) {
    const Fp2<C> xi = xi_const<C>();
    out[0] = Fp2<C>::one() + l0.c * l1.c * xi;
    out[1] = l0.b + l1.b;
    out[2] = l0.b * l1.b;
    out[3] = l0.c + l1.c;
    out[4] = l0.b * l1.c + l1.b * l0.c;
}

// mul_by_01234 (bn254/pairing.rs, hand-derived sparse multiplication)
template <class C>
Fp12<C> mul_by_01234(const Fp12<C>& f, const Fp2<C> x[5]) {
    const Fp2<C> xi = xi_const<C>();
    const Fp2<C>& o0 = x[0];
    const Fp2<C>& o1 = x[2];
    const Fp2<C>& o2 = x[4];
    const Fp2<C>& o3 = x[1];
    const Fp2<C>& o4 = x[3];
    const Fp2<C>& s0 = f.c[0];
    const Fp2<C>& s1 = f.c[2];
    const Fp2<C>& s2 = f.c[4];
    const Fp2<C>& s3 = f.c[1];
    const Fp2<C>& s4 = f.c[3];
    const Fp2<C>& s5 = f.c[5];
    Fp2<C> c00 = s0 * o0 + xi * (s1 * o2 + s2 * o1 + s4 * o4 + s5 * o3);
    Fp2<C> c01 = s0 * o1 + s1 * o0 + s3 * o3 + xi * (s2 * o2 + s5 * o4);
    Fp2<C> c02 = s0 * o2 + s1 * o1 + s2 * o0 + s3 * o4 + s4 * o3;
    Fp2<C> c10 = s0 * o3 + s3 * o0 + xi * (s2 * o4 + s4 * o2 + s5 * o1);
    Fp2<C> c11 = s0 * o4 + s1 * o3 + s3 * o1 + s4 * o0 + xi * (s5 * o2);
    Fp2<C> c12 = s1 * o4 + s2 * o3 + s3 * o2 + s4 * o1 + s5 * o0;
    Fp12<C> r;
    r.c[0] = c00;
    r.c[1] = c10;
    r.c[2] = c01;
    r.c[3] = c11;
    r.c[4] = c02;
    r.c[5] = c12;
    return r;
}

// mul_023_by_023 (bls12_381/pairing.rs): [x0, x2, x3, x4, x5]
template <class C>
void mul_023_by_023(const Line<C>& l0, const Line<C>& l1, Fp2<C> out[5]) {
    const Fp2<C> xi = xi_const<C>();
    out[0] = l0.c * l1.c + xi;
    out[1] = l0.c * l1.b + l1.c * l0.b;
    out[2] = l0.c + l1.c;
    out[3] = l0.b * l1.b;
    out[4] = l0.b + l1.b;
}

// mul_by_02345 (bls12_381/pairing.rs, hand-derived sparse multiplication)
template <class C>
Fp12<C> mul_by_02345(const Fp12<C>& f, const Fp2<C> x[5]) {
    const Fp2<C> xi = xi_const<C>();
    const Fp2<C>& o0 = x[0];
    const Fp2<C>& o1 = x[1];
    const Fp2<C>& o2 = x[3];
    const Fp2<C>& o4 = x[2];
    const Fp2<C>& o5 = x[4];
    const Fp2<C>& s0 = f.c[0];
    const Fp2<C>& s1 = f.c[2];
    const Fp2<C>& s2 = f.c[4];
    const Fp2<C>& s3 = f.c[1];
    const Fp2<C>& s4 = f.c[3];
    const Fp2<C>& s5 = f.c[5];
    Fp2<C> c00 = s0 * o0 + xi * (s1 * o2 + s2 * o1 + s3 * o5 + s4 * o4);
    Fp2<C> c01 = s0 * o1 + s1 * o0 + xi * (s2 * o2 + s4 * o5 + s5 * o4);
    Fp2<C> c02 = s0 * o2 + s1 * o1 + s2 * o0 + s3 * o4 + xi * (s5 * o5);
    Fp2<C> c10 = s3 * o0 + xi * (s1 * o5 + s2 * o4 + s4 * o2 + s5 * o1);
    Fp2<C> c11 = s0 * o4 + s3 * o1 + s4 * o0 + xi * (s2 * o5 + s5 * o2);
    Fp2<C> c12 = s0 * o5 + s1 * o4 + s3 * o2 + s4 * o1 + s5 * o0;
    Fp12<C> r;
    r.c[0] = c00;
    r.c[1] = c10;
    r.c[2] = c01;
    r.c[3] = c11;
    r.c[4] = c02;
    r.c[5] = c12;
    return r;
}

/* ─────────────────────────── curve-specific glue ──────────────────────── */

// Bounded pair count: the EVM ecpairing input is gas-bounded far below this,
// and KZG uses exactly 2. Avoids heap allocation in the guest.
constexpr size_t MAX_PAIRS = 16;

template <class C, bool D_TYPE>
Fp12<C> evaluate_lines_vec(Fp12<C> f, Line<C>* lines, size_t n) {
    if (n % 2 == 1) {
        // multiply in the last line individually
        const Line<C>& l = lines[n - 1];
        Fp12<C> lf = D_TYPE ? from_line_d<C>(l) : from_line_m<C>(l);
        f = fp12_mul(lf, f);
        n -= 1;
    }
    for (size_t i = 0; i < n; i += 2) {
        Fp2<C> prod[5];
        if (D_TYPE) {
            mul_013_by_013(lines[i], lines[i + 1], prod);
            f = mul_by_01234(f, prod);
        } else {
            mul_023_by_023(lines[i], lines[i + 1], prod);
            f = mul_by_02345(f, prod);
        }
    }
    return f;
}

// HintFinalExp: rd=x0, rs1/rs2 point to (u64 ptr, u64 count) fat pointers.
// The host writes c || u as raw canonical LE coefficient bytes into the
// hint stream (no length prefix).
template <class C>
void hint_final_exp(
    const AffP<C>* P, const AffP2<C>* Q, size_t n, Fp12<C>& c, Fp12<C>& u) {
    struct {
        uint64_t ptr;
        uint64_t len;
    } p_fat{reinterpret_cast<uint64_t>(P), n}, q_fat{reinterpret_cast<uint64_t>(Q), n};
    if constexpr (C::PAIRING_IDX == 0) {
        asm volatile(".insn r 0x2b, 0b011, (0*16 + 0), x0, %0, %1" ::"r"(&p_fat), "r"(&q_fat)
                     : "memory");
    } else {
        asm volatile(".insn r 0x2b, 0b011, (1*16 + 0), x0, %0, %1" ::"r"(&p_fat), "r"(&q_fat)
                     : "memory");
    }
    alignas(8) uint8_t buf[2 * 12 * C::NB];
    openvm::hint_buffer_chunked(buf, sizeof(buf) / openvm::HINT_WORD_BYTES);
    std::memcpy(&c, buf, 12 * C::NB);
    std::memcpy(&u, buf + 12 * C::NB, 12 * C::NB);
}

// Shared multi-Miller loop with optional embedded exponent
// (miller_loop.rs::multi_miller_loop_embedded_exp). Infinity pairs must be
// filtered by the caller. `Curve` provides pre_loop/post_loop/D_TYPE.
template <class C, class Curve>
Fp12<C> multi_miller_loop_embedded_exp(
    const AffP<C>* P, const AffP2<C>* Q, size_t n, const Fp12<C>* c /* nullable */) {
    Fp<C>* x_over_y = new Fp<C>[n];
    Fp<C>* y_inv = new Fp<C>[n];
    const Fp<C> fone = Fp<C>::one();
    for (size_t i = 0; i < n; ++i) {
        C::fdiv(x_over_y[i].b, P[i].x.b, P[i].y.b);
        C::fdiv(y_inv[i].b, fone.b, P[i].y.b);
    }
    Fp12<C> c_inv = c ? fp12_inv(*c) : Fp12<C>::one();

    AffP2<C>* Q_acc = new AffP2<C>[n];
    for (size_t i = 0; i < n; ++i) Q_acc[i] = Q[i];
    Line<C>* lines = new Line<C>[2 * n];

    Fp12<C> f = Curve::pre_loop(Q_acc, Q, n, c, x_over_y, y_inv, lines);

    const int8_t* enc = Curve::PSB;
    for (int i = Curve::PSB_LEN - 3; i >= 0; --i) {
        f = fp12_mul(f, f);

        size_t n_lines = 0;

        if (enc[i] == 0) {
            for (size_t j = 0; j < n; ++j) {
                AffP2<C> out;
                Line<C> l;
                miller_double_step<C>(Q_acc[j], out, l);
                Q_acc[j] = out;
                lines[n_lines++] = evaluate_line<C>(l, x_over_y[j], y_inv[j]);
            }
        } else {
            if (c)
                f = fp12_mul(f, enc[i] == 1 ? *c : c_inv);
            for (size_t j = 0; j < n; ++j) {
                AffP2<C> q_signed = enc[i] == 1 ? Q[j] : Q[j].neg();
                AffP2<C> out;
                Line<C> l0, l1;
                miller_double_and_add_step<C>(Q_acc[j], q_signed, out, l0, l1);
                Q_acc[j] = out;
                lines[n_lines++] = evaluate_line<C>(l0, x_over_y[j], y_inv[j]);
                lines[n_lines++] = evaluate_line<C>(l1, x_over_y[j], y_inv[j]);
            }
        }
        f = evaluate_lines_vec<C, Curve::D_TYPE>(f, lines, n_lines);
    }

    f = Curve::post_loop(f, Q_acc, Q, n, x_over_y, y_inv, lines);
    delete[] lines;
    delete[] Q_acc;
    delete[] y_inv;
    delete[] x_over_y;
    return f;
}

/* ── bn254 curve policy ── */
struct Bn254Curve {
    using C = BnCfg;
    static constexpr bool D_TYPE = true;
    static constexpr const int8_t* PSB = opc::BN254_PSEUDO_BINARY;
    static constexpr int PSB_LEN = 66;

    // pre_loop (bn254/pairing.rs): f = c^2 (or 1), then one double step.
    static Fp12<C> pre_loop(AffP2<C>* Q_acc, const AffP2<C>*, size_t n, const Fp12<C>* c,
        const Fp<C>* x_over_y, const Fp<C>* y_inv, Line<C>* lines) {
        Fp12<C> f = c ? fp12_mul(*c, *c) : Fp12<C>::one();
        size_t n_lines = 0;
        for (size_t j = 0; j < n; ++j) {
            AffP2<C> out;
            Line<C> l;
            miller_double_step<C>(Q_acc[j], out, l);
            Q_acc[j] = out;
            lines[n_lines++] = evaluate_line<C>(l, x_over_y[j], y_inv[j]);
        }
        return evaluate_lines_vec<C, D_TYPE>(f, lines, n_lines);
    }

    // post_loop (bn254/pairing.rs): the two extra Frobenius add steps.
    static Fp12<C> post_loop(const Fp12<C>& f_in, AffP2<C>* Q_acc, const AffP2<C>* Q, size_t n,
        const Fp<C>* x_over_y, const Fp<C>* y_inv, Line<C>* lines) {
        const size_t fp2b = 2 * C::NB;
        Fp2<C> x_to_q_minus_1_over_3, x_to_q_sq_minus_1_over_3, xi_to_q_minus_1_over_2;
        std::memcpy(x_to_q_minus_1_over_3.b, opc::BN254_FQ6_C1_1, fp2b);
        std::memcpy(x_to_q_sq_minus_1_over_3.b, opc::BN254_FQ6_C1_2, fp2b);
        std::memcpy(xi_to_q_minus_1_over_2.b, opc::BN254_XI_TO_Q_MINUS_1_OVER_2, fp2b);

        size_t n_lines = 0;

        // q1 = (conj(x) * FQ6_C1[1], conj(y) * XI_TO_Q_MINUS_1_OVER_2)
        for (size_t j = 0; j < n; ++j) {
            AffP2<C> q1{Q[j].x.conjugate() * x_to_q_minus_1_over_3,
                Q[j].y.conjugate() * xi_to_q_minus_1_over_2};
            AffP2<C> out;
            Line<C> l;
            miller_add_step<C>(Q_acc[j], q1, out, l);
            Q_acc[j] = out;
            lines[n_lines++] = evaluate_line<C>(l, x_over_y[j], y_inv[j]);
        }
        // q2 = (x * FQ6_C1[2], y)
        for (size_t j = 0; j < n; ++j) {
            AffP2<C> q2{Q[j].x * x_to_q_sq_minus_1_over_3, Q[j].y};
            AffP2<C> out;
            Line<C> l;
            miller_add_step<C>(Q_acc[j], q2, out, l);
            Q_acc[j] = out;
            lines[n_lines++] = evaluate_line<C>(l, x_over_y[j], y_inv[j]);
        }
        return evaluate_lines_vec<C, D_TYPE>(f_in, lines, n_lines);
    }
};

/* ── bls12-381 curve policy ── */
struct BlsCurve {
    using C = BlsCfg;
    static constexpr bool D_TYPE = false;
    static constexpr const int8_t* PSB = opc::BLS_PSEUDO_BINARY;
    static constexpr int PSB_LEN = 64;

    // pre_loop (bls12_381/pairing.rs): f = c^3 (or 1), then a double step
    // and an add step (first pseudo-binary digit is 1).
    static Fp12<C> pre_loop(AffP2<C>* Q_acc, const AffP2<C>* Q, size_t n, const Fp12<C>* c,
        const Fp<C>* x_over_y, const Fp<C>* y_inv, Line<C>* lines) {
        Fp12<C> f;
        if (c) {
            Fp12<C> c2 = fp12_mul(*c, *c);
            f = fp12_mul(c2, *c);
        } else {
            f = Fp12<C>::one();
        }
        size_t n_lines = 0;
        for (size_t j = 0; j < n; ++j) {
            AffP2<C> out;
            Line<C> l;
            miller_double_step<C>(Q_acc[j], out, l);
            Q_acc[j] = out;
            lines[n_lines++] = evaluate_line<C>(l, x_over_y[j], y_inv[j]);
        }
        for (size_t j = 0; j < n; ++j) {
            AffP2<C> out;
            Line<C> l;
            miller_add_step<C>(Q_acc[j], Q[j], out, l);
            Q_acc[j] = out;
            lines[n_lines++] = evaluate_line<C>(l, x_over_y[j], y_inv[j]);
        }
        return evaluate_lines_vec<C, D_TYPE>(f, lines, n_lines);
    }

    // post_loop: conjugate (negative seed).
    static Fp12<C> post_loop(const Fp12<C>& f, AffP2<C>*, const AffP2<C>*, size_t,
        const Fp<C>*, const Fp<C>*, Line<C>*) {
        return f.conjugate();
    }
};

/* ─────────────────────── pairing checks (per curve) ───────────────────── */

// bn254 (pairing.rs try_honest_pairing_check + exp_check_fallback).
bool bn254_check_filtered(const AffP<BnCfg>* P, const AffP2<BnCfg>* Q, size_t n) {
    using C = BnCfg;
    if (n == 0)
        return true;

    Fp12<C> c, u;
    hint_final_exp<C>(P, Q, n, c, u);

    bool honest = !c.is_zero();
    // u must lie in the proper Fp6 subfield.
    if (honest)
        for (int i : {1, 3, 5})
            if (!u.c[i].is_zero()) {
                honest = false;
                break;
            }

    if (honest) {
        const uint8_t* frob_rows[3] = {opc::BN254_FROB_1, opc::BN254_FROB_2, opc::BN254_FROB_3};
        Fp12<C> c_inv = fp12_inv(c);
        // c_mul = c^-{q^3 - q^2 + q}
        Fp12<C> c_q3_inv = fp12_frobenius<C>(c_inv, 3, frob_rows);
        Fp12<C> c_q2 = fp12_frobenius<C>(c, 2, frob_rows);
        Fp12<C> c_q_inv = fp12_frobenius<C>(c_inv, 1, frob_rows);
        Fp12<C> c_mul = fp12_mul(fp12_mul(c_q3_inv, c_q2), c_q_inv);

        Fp12<C> fc = multi_miller_loop_embedded_exp<C, Bn254Curve>(P, Q, n, &c_inv);
        if (fp12_mul(fp12_mul(fc, c_mul), u).eq(Fp12<C>::one()))
            return true;
        // fall through to the fallback on a dishonest hint
    }

    Fp12<C> f = multi_miller_loop_embedded_exp<C, Bn254Curve>(P, Q, n, nullptr);
    return fp12_pow_be(f, opc::BN254_FINAL_EXPONENT_BE, sizeof(opc::BN254_FINAL_EXPONENT_BE))
        .eq(Fp12<C>::one());
}

// bls12-381 (bls12_381/pairing.rs try_honest_pairing_check).
bool bls_check_filtered(const AffP<BlsCfg>* P, const AffP2<BlsCfg>* Q, size_t n) {
    using C = BlsCfg;
    if (n == 0)
        return true;

    Fp12<C> c, s;
    hint_final_exp<C>(P, Q, n, c, s);

    bool honest = true;
    for (int i : {1, 3, 5})
        if (!s.c[i].is_zero()) {
            honest = false;
            break;
        }

    if (honest) {
        const uint8_t* frob_rows[3] = {opc::BLS_FROB_1, nullptr, nullptr};
        Fp12<C> c_q = fp12_frobenius<C>(c, 1, frob_rows);
        Fp12<C> c_conj = c.conjugate();
        if (!c_conj.is_zero()) {
            Fp12<C> c_conj_inv = fp12_inv(c_conj);
            Fp12<C> fc = multi_miller_loop_embedded_exp<C, BlsCurve>(P, Q, n, &c_conj_inv);
            if (fp12_mul(fc, s).eq(c_q))
                return true;
        }
        // fall through on zero/dishonest witness
    }

    Fp12<C> f = multi_miller_loop_embedded_exp<C, BlsCurve>(P, Q, n, nullptr);
    return fp12_pow_be(f, opc::BLS_FINAL_EXPONENT_BE, sizeof(opc::BLS_FINAL_EXPONENT_BE))
        .eq(Fp12<C>::one());
}

// Filter infinity pairs into local arrays (multi_miller_loop precondition).
template <class C, class CheckFn>
bool pairing_check_bytes(
    const uint8_t* p_points, const uint8_t* q_points, size_t n, CheckFn check) {
    if (n == 0)
        return true;
    AffP<C>* P = new AffP<C>[n];
    AffP2<C>* Q = new AffP2<C>[n];
    size_t m = 0;
    for (size_t i = 0; i < n; ++i) {
        AffP<C> p;
        AffP2<C> q;
        std::memcpy(&p, p_points + i * 2 * C::NB, 2 * C::NB);
        std::memcpy(&q, q_points + i * 4 * C::NB, 4 * C::NB);
        if (p.is_infinity() || q.is_infinity())
            continue;
        P[m] = p;
        Q[m] = q;
        ++m;
    }
    const bool ok = check(P, Q, m);
    delete[] Q;
    delete[] P;
    return ok;
}

/* ─────────────────────────── KZG (bls12-381) ──────────────────────────── */

using BFp = Fp<BlsCfg>;
using BG1 = AffP<BlsCfg>;
using BFp2 = Fp2<BlsCfg>;
using BG2 = AffP2<BlsCfg>;

BFp bfp_from_le(const uint8_t* le) {
    BFp r;
    std::memcpy(r.b, le, 48);
    return r;
}

// Compare 48-byte little-endian values; returns <0/0/>0.
int cmp_le(const uint8_t* a, const uint8_t* b, size_t n) {
    for (size_t i = n; i-- > 0;) {
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

BFp bfp_mul(const BFp& a, const BFp& b) { BFp r; BlsCfg::fmul(r.b, a.b, b.b); return r; }
BFp bfp_add(const BFp& a, const BFp& b) { BFp r; BlsCfg::fadd(r.b, a.b, b.b); return r; }
BFp bfp_sub(const BFp& a, const BFp& b) { BFp r; BlsCfg::fsub(r.b, a.b, b.b); return r; }

BFp bfp_pow_be(const BFp& x, const uint8_t* exp, size_t exp_len) {
    BFp acc = BFp::one();
    bool started = false;
    for (size_t i = 0; i < exp_len; ++i) {
        for (int bit = 7; bit >= 0; --bit) {
            if (started)
                acc = bfp_mul(acc, acc);
            if ((exp[i] >> bit) & 1) {
                if (started)
                    acc = bfp_mul(acc, x);
                else {
                    acc = x;
                    started = true;
                }
            }
        }
    }
    return acc;
}

// G1 group ops over the native short-Weierstrass instructions, with the
// same identity / equal-x branching as the other native-EC helpers.
void bg1_add(BG1& r, const BG1& p) {
    if (p.is_infinity())
        return;
    if (r.is_infinity()) {
        r = p;
        return;
    }
    if (r.x.eq(p.x)) {
        if (r.y.eq(p.y)) {
            openvm::bls_ec_double(&r, &r);
            return;
        }
        // r == -p
        r.x = BFp::zero();
        r.y = BFp::zero();
        return;
    }
    openvm::bls_ec_add_ne(&r, &r, &p);
}

BG1 bg1_neg(const BG1& p) {
    if (p.is_infinity())
        return p;
    BG1 r = p;
    BlsCfg::fsub(r.y.b, BFp::zero().b, p.y.b);
    return r;
}

// [k]P, k as big-endian bytes, MSB-first double-and-add.
BG1 bg1_mul_be(const BG1& p, const uint8_t* k, size_t k_len) {
    BG1 r{BFp::zero(), BFp::zero()};
    if (p.is_infinity())
        return r;
    bool started = false;
    for (size_t i = 0; i < k_len; ++i) {
        for (int bit = 7; bit >= 0; --bit) {
            if (started && !r.is_infinity())
                openvm::bls_ec_double(&r, &r);
            if ((k[i] >> bit) & 1) {
                if (!started) {
                    r = p;
                    started = true;
                } else {
                    bg1_add(r, p);
                }
            }
        }
    }
    return r;
}

// Software G2 affine group ops over the Fp2 instructions.
void bg2_add(BG2& r, const BG2& p) {
    if (p.is_infinity())
        return;
    if (r.is_infinity()) {
        r = p;
        return;
    }
    if (r.x.eq(p.x)) {
        if (r.y.eq(p.y)) {
            // double: lambda = 3x^2 / 2y
            BFp2 xx = r.x * r.x;
            BFp2 lambda = fp2_div(xx + xx + xx, r.y + r.y);
            BFp2 x2 = lambda * lambda - (r.x + r.x);
            BFp2 y2 = lambda * (r.x - x2) - r.y;
            r = {x2, y2};
            return;
        }
        r = {BFp2::zero(), BFp2::zero()};
        return;
    }
    BFp2 lambda = fp2_div(p.y - r.y, p.x - r.x);
    BFp2 x2 = lambda * lambda - r.x - p.x;
    BFp2 y2 = lambda * (r.x - x2) - r.y;
    r = {x2, y2};
}

BG2 bg2_neg(const BG2& p) {
    if (p.is_infinity())
        return p;
    return {p.x, p.y.neg()};
}

BG2 bg2_mul_be(const BG2& p, const uint8_t* k, size_t k_len) {
    BG2 r{BFp2::zero(), BFp2::zero()};
    bool started = false;
    for (size_t i = 0; i < k_len; ++i) {
        for (int bit = 7; bit >= 0; --bit) {
            if (started && !r.is_infinity()) {
                BG2 d = r;
                bg2_add(d, r);  // handles the equal-x doubling branch
                r = d;
            }
            if ((k[i] >> bit) & 1) {
                if (!started) {
                    r = p;
                    started = true;
                } else {
                    bg2_add(r, p);
                }
            }
        }
    }
    return r;
}

// G1 subgroup membership (curve-utils SubgroupCheck for bls G1, eprint
// 2021/1130 §6): with x = |seed|, reject if [x]P == P != O; accept iff
// -[x]([x]P) == sigma(P) where sigma(x, y) = (BETA * x, y).
bool bg1_in_subgroup(const BG1& p) {
    if (p.is_infinity())
        return true;
    uint8_t x_be[8];
    for (int i = 0; i < 8; ++i)
        x_be[i] = static_cast<uint8_t>(opc::BLS_SEED_ABS >> (8 * (7 - i)));
    BG1 xp = bg1_mul_be(p, x_be, 8);
    if (xp.x.eq(p.x) && xp.y.eq(p.y))
        return false;
    BG1 x2p = bg1_mul_be(xp, x_be, 8);
    BG1 lhs = bg1_neg(x2p);
    BG1 sigma{bfp_mul(bfp_from_le(opc::BLS_BETA), p.x), p.y};
    return lhs.x.eq(sigma.x) && lhs.y.eq(sigma.y);
}

// ZCash-flag compressed G1 parsing + subgroup check. Returns false on any
// invalid encoding.
bool parse_g1_compressed(const uint8_t in[48], BG1& out, bool& is_inf) {
    const uint8_t flags = in[0];
    const bool f_compressed = (flags & 0x80) != 0;
    const bool f_infinity = (flags & 0x40) != 0;
    const bool f_sort = (flags & 0x20) != 0;
    if (!f_compressed)
        return false;
    if (f_infinity) {
        if ((flags & 0x3f) != 0)
            return false;
        for (int i = 1; i < 48; ++i)
            if (in[i] != 0)
                return false;
        out = {BFp::zero(), BFp::zero()};
        is_inf = true;
        return true;
    }
    is_inf = false;
    // x: big-endian with the top 3 bits masked.
    uint8_t x_le[48];
    for (int i = 0; i < 48; ++i)
        x_le[i] = in[47 - i];
    x_le[47] &= 0x1f;
    if (cmp_le(x_le, openvm::ecc_detail::BLS_FP_LE, 48) >= 0)
        return false;
    BFp x = bfp_from_le(x_le);

    // y^2 = x^3 + 4; y = (x^3+4)^((p+1)/4), then verify.
    BFp x3 = bfp_mul(bfp_mul(x, x), x);
    BFp rhs = bfp_add(x3, bfp_from_le(opc::BLS_B_LE));
    BFp y = bfp_pow_be(rhs, opc::BLS_SQRT_EXP_BE, sizeof(opc::BLS_SQRT_EXP_BE));
    if (!bfp_mul(y, y).eq(rhs))
        return false;  // not a square -> x not on curve

    // Choose the candidate matching the sort flag: flag set means y is the
    // lexicographically larger of (y, p - y).
    BFp y_neg = bfp_sub(BFp::zero(), y);
    const bool y_is_larger = cmp_le(y.b, y_neg.b, 48) > 0;
    if (y_is_larger != f_sort)
        y = y_neg;

    out = {x, y};
    return bg1_in_subgroup(out);
}

}  // namespace

namespace openvm_pairing {

bool bn254_pairing_check(const uint8_t* p_points, const uint8_t* q_points, size_t n) noexcept {
    return pairing_check_bytes<BnCfg>(p_points, q_points, n,
        [](const AffP<BnCfg>* P, const AffP2<BnCfg>* Q, size_t m) {
            return bn254_check_filtered(P, Q, m);
        });
}

bool bls_pairing_check(const uint8_t* p_points, const uint8_t* q_points, size_t n) noexcept {
    return pairing_check_bytes<BlsCfg>(p_points, q_points, n,
        [](const AffP<BlsCfg>* P, const AffP2<BlsCfg>* Q, size_t m) {
            return bls_check_filtered(P, Q, m);
        });
}

bool kzg_verify_proof(const uint8_t commitment[48], const uint8_t z_be[32],
    const uint8_t y_be[32], const uint8_t proof[48]) noexcept {
    // Scalars must be canonical (< r).
    auto scalar_ok = [](const uint8_t* be) {
        for (int i = 0; i < 32; ++i) {
            if (be[i] < opc::BLS_R_BE[i])
                return true;
            if (be[i] > opc::BLS_R_BE[i])
                return false;
        }
        return false;  // equal to r -> not reduced
    };
    if (!scalar_ok(z_be) || !scalar_ok(y_be))
        return false;

    BG1 C_pt, Pi;
    bool c_inf = false, pi_inf = false;
    if (!parse_g1_compressed(commitment, C_pt, c_inf))
        return false;
    if (!parse_g1_compressed(proof, Pi, pi_inf))
        return false;

    // Constants.
    BG1 g1_gen;
    std::memcpy(&g1_gen, opc::BLS_G1_GEN, sizeof(g1_gen));
    BG2 g2_gen, tau_g2;
    std::memcpy(&g2_gen, opc::BLS_G2_GEN, sizeof(g2_gen));
    std::memcpy(&tau_g2, opc::BLS_TAU_G2, sizeof(tau_g2));

    // C - [y]G1
    BG1 y_g1 = bg1_mul_be(g1_gen, y_be, 32);
    BG1 c_minus_y = c_inf ? BG1{BFp::zero(), BFp::zero()} : C_pt;
    bg1_add(c_minus_y, bg1_neg(y_g1));

    // [tau]G2 - [z]G2
    BG2 z_g2 = bg2_mul_be(g2_gen, z_be, 32);
    BG2 x_minus_z = tau_g2;
    bg2_add(x_minus_z, bg2_neg(z_g2));

    // e(-(C - [y]G1), G2) * e(pi, [tau - z]G2) == 1
    BG1 P[2] = {bg1_neg(c_minus_y), pi_inf ? BG1{BFp::zero(), BFp::zero()} : Pi};
    BG2 Q[2] = {g2_gen, x_minus_z};

    // Filter infinity pairs.
    AffP<BlsCfg> Pf[2];
    AffP2<BlsCfg> Qf[2];
    size_t m = 0;
    for (int i = 0; i < 2; ++i) {
        if (P[i].is_infinity() || Q[i].is_infinity())
            continue;
        Pf[m] = P[i];
        Qf[m] = Q[i];
        ++m;
    }
    return bls_check_filtered(Pf, Qf, m);
}

}  // namespace openvm_pairing
