from bitcoin import *

def hash_to_num(x):
    return sha256(x)

def hash_to_pubkey(x):
    x = hash_to_int(sha256(x))
    while 1:
        xcubedaxb = (x*x*x+A*x+B) % P
        beta = pow(xcubedaxb, (P+1)//4, P)
        y = beta if beta % 2 else (P - beta)
        # Return if the result is not a quadratic residue
        if (xcubedaxb - y*y) % P == 0:
            return encode_pubkey((x, y), 'hex')
        x = (x + 1) % P

def sign(message, priv, pubs):
    n = len(pubs)
    my_pub = privtopub(priv)
    my_index = pubs.index(my_pub)
    assert my_index >= 0
    I = multiply(hash_to_pubkey(my_pub), priv)
    k = random_key()
    e = [None] * n
    orig_left = hash_to_num(message + privtopub(k) + multiply(hash_to_pubkey(my_pub), k))
    orig_right = hash_to_num(orig_left)
    e[my_index] = {"left": orig_left, "right": orig_right}
    s = [None] * n
    print "Signing"
    for i in list(range(my_index + 1, n)) + list(range(my_index + 1)):
        prev_i = (i - 1) % n
        if i == my_index:
            s[prev_i] = add_privkeys(k, mul_privkeys(e[prev_i]["right"], priv))
        else:
            s[prev_i] = random_key()
        left = hash_to_num(message + \
            subtract_pubkeys(privtopub(s[prev_i]), multiply(pubs[i], e[prev_i]["right"])) + \
            subtract_pubkeys(multiply(hash_to_pubkey(pubs[i]), s[prev_i]), multiply(I, e[prev_i]["right"])))
        right = hash_to_num(left)
        e[i] = {"left": left, "right": right}
    for i in range(n):
        print e[i], s[i]
    assert (left, right) == (orig_left, orig_right)
    return (e[0]["left"], s, I)

def verify(proof, message, pubs):
    n = len(pubs)
    e = [None] * (n + 1)
    left, s, I = proof 
    right = hash_to_num(left)
    e[0] = {"left": left, "right": right}
    print "Verifying"
    for i in range(1, n + 1):
        prev_i = (i - 1) % n
        print e[prev_i], s[prev_i]
        left = hash_to_num(message + \
            subtract_pubkeys(privtopub(s[prev_i]), multiply(pubs[i % n], e[prev_i]["right"])) + \
            subtract_pubkeys(multiply(hash_to_pubkey(pubs[i % n]), s[prev_i]), multiply(I, e[prev_i]["right"])))
        right = hash_to_num(left)
        e[i] = {"left": left, "right": right}
    assert e[n] == e[0]
    return I

privs = [random_key() for i in range(10)]
pubs = map(privtopub, privs)
message = "foo"
sigs = [sign(message, priv, pubs) for priv in privs]
i_s = [verify(sig, message, pubs) for sig in sigs]
assert len(set(i_s)) == len(i_s)
