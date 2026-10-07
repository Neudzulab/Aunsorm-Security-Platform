"""Offline reference implementation; never a production RNG or entropy estimator."""


def integer(name, value, minimum):
    """Reject booleans, nonintegers and out-of-domain parameters."""
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")


def output_budget(input_bits, certified_min_entropy_bits, security_bits):
    """Conservative m=k-2s; requires an externally certified integer bound k.

    No input measurements, IID inference, seed generation or certification occur.
    Under the documented classical assumptions, distance <= 2**(-s-1).
    """
    integer("input_bits", input_bits, 1)
    integer("certified_min_entropy_bits", certified_min_entropy_bits, 0)
    integer("security_bits", security_bits, 1)
    if certified_min_entropy_bits > input_bits:
        raise ValueError("min-entropy cannot exceed input length")
    m = certified_min_entropy_bits - 2 * security_bits
    if m <= 0:
        raise ValueError("insufficient certified entropy for requested security")
    return m


def extract(source, seed, input_bits, output_bits):
    """Compute y_i = XOR_j seed[n-1+i-j] * source[j], LSB index zero.

    A seed has exactly n+m-1 significant bit positions (leading zeros allowed).
    The caller must supply a uniformly random seed independent of the source
    and adversary's information. Integer arguments cannot enforce this condition.
    Python big integers are neither constant-time nor securely zeroized.
    """
    integer("input_bits", input_bits, 1)
    integer("output_bits", output_bits, 1)
    if output_bits > input_bits:
        raise ValueError("extraction output must not exceed input length")
    integer("source", source, 0)
    integer("seed", seed, 0)
    d = input_bits + output_bits - 1
    if source.bit_length() > input_bits or seed.bit_length() > d:
        raise ValueError("source or seed exceeds declared bit length")
    reversed_seed = int(format(seed, f"0{d}b")[::-1], 2)
    mask = (1 << input_bits) - 1
    result = 0
    for i in range(output_bits):
        row = (reversed_seed >> (output_bits - 1 - i)) & mask
        result |= ((row & source).bit_count() & 1) << i
    return result
