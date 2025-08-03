from typing import Literal, NamedTuple, TypeVar

import json

class MinimalParameter(NamedTuple):
    k: int
    modulus_q: int
    primitive_root: int

SecurityLevel = Literal[128, 160, 192, 224,256]

minimal_params: dict[SecurityLevel, MinimalParameter] = dict({
    128: MinimalParameter(10, 1152921504606846883, 3),
    160: MinimalParameter(10,1180591620717411303423,5),
    192: MinimalParameter(10,1180591620717411303423,5),
    224: MinimalParameter(11,340282366920938463463374607431768211293,7),
    256: MinimalParameter(11,340282366920938463463374607431768211293,7)
})

def gen_twiddle_lut(n: int, w_primitive: int, modulo: int):
    for i in range(0,n):
        yield pow(w_primitive,i,modulo)

class NttParameters:
    def __init__(self, modulus_q: int, w_primitive: int, w_inv_primitive: int, twiddle_lut_n1: list[int], twiddle_lut_n2: list[int], inv_twiddle_lut_n1: list[int], inv_twiddle_lut_n2: list[int]):
        self.modulus_q: int = modulus_q
        self.w_primitive: int = w_primitive
        self.w_inv_primitive: int = w_inv_primitive
        self.twiddle_lut_n1: list[int] = twiddle_lut_n1
        self.twiddle_lut_n2: list[int] = twiddle_lut_n2
        self.inv_twiddle_lut_n1: list[int] = inv_twiddle_lut_n1
        self.inv_twiddle_lut_n2: list[int] = inv_twiddle_lut_n2
        


def get_ntt_params(params: MinimalParameter):
    k = params.k
    q = params.modulus_q
    n: int = pow(2,k)
    root = params.primitive_root

    w_primitive = pow(root,(q-1) // n,q)
    w_inv_primitive = pow(w_primitive, q-2,q)

    k1 = k // 2
    k2 = k - k1

    n1: int = pow(2,k1)
    n2: int = pow(2,k2)

    w_n2 = pow(w_primitive, n1, q)
    twiddle_lut_n2 = list(gen_twiddle_lut(n2,w_n2,q))

    w_n1 = pow(w_primitive, n2, q)
    twiddle_lut_n1 = list(gen_twiddle_lut(n1,w_n1,q))

    w_inv_n2 = pow(w_inv_primitive, n1, q)
    inv_twiddle_lut_n2 = list(gen_twiddle_lut(n2,w_inv_n2,q))

    w_inv_n1 = pow(w_inv_primitive, n2, q)
    inv_twiddle_lut_n1 = list(gen_twiddle_lut(n1,w_inv_n1,q))

    return NttParameters(q, w_primitive,w_inv_primitive,twiddle_lut_n1,twiddle_lut_n2,inv_twiddle_lut_n1,inv_twiddle_lut_n2)

T = TypeVar('T')
def concat_lists(*lists: list[T]):
    for ls in lists:
        for item in ls:
            yield item

def get_log2_of_minimum_bits_count(n: int) -> int:
    if n < 0:
        raise ArithmeticError
    i: int = 0
    while n >= pow(2,pow(2,i)):
        i = i + 1
    else:
        return i



class NttParametersEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, NttParameters):
            bound_rem, bound_max = map(get_log2_of_minimum_bits_count,
                (
                    (obj.modulus_q - 1),
                    max(set(concat_lists(obj.twiddle_lut_n1, obj.twiddle_lut_n2, obj.inv_twiddle_lut_n1, obj.inv_twiddle_lut_n2)))
                )
            )
            
            needed_max_bits: int = pow(2,min(bound_max, bound_rem))

            return {
                "needed_max_bits": needed_max_bits,
                "modulus_q": obj.modulus_q,
                "w_primitive": obj.w_primitive,
                "w_inv_primitive": obj.w_inv_primitive,
                "twiddle_lut_n1": obj.twiddle_lut_n1,
                "twiddle_lut_n2": obj.twiddle_lut_n2,
                "inv_twiddle_lut_n1": obj.inv_twiddle_lut_n1,
                "inv_twiddle_lut_n2": obj.inv_twiddle_lut_n2,
            }
        return super().default(obj)

if __name__ == '__main__':
    ntt_params = { level: get_ntt_params(min_param) for level, min_param in minimal_params.items() }

    with open("ntt_params.json","w") as f:
        json.dump(ntt_params,f,indent=4,sort_keys=False,cls=NttParametersEncoder)