from xhd_wallet_api_py import (
    derive_path,
    key_gen,
    raw_sign,
    sign,
    DerivationScheme,
    KeyContext,
    XPRV_SIZE,
)

VALID_ROOT_KEY = bytes.fromhex(
    "f8a29231ee38d6c5bf715d5bac21c750577aa3798b22d79d65bf97d6fade"
    "a15adcd1ee1abdf78bd4be64731a12deb94d3671784112eb6f364b871851"
    "fd1c9a247384db9ad6003bbd08b3b1ddc0d07a597293ff85e961bf252b33"
    "1262eddfad0d"
)

ROOT_KEY_HEX = (
    "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f469"
    "4592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796"
    "b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946"
)

BIP44_PATH = [0x8000002c, 0x8000011b, 0x80000000, 0, 0]

def test_derive_path_success():
    derived = derive_path(VALID_ROOT_KEY, BIP44_PATH, DerivationScheme.Peikert)
    assert len(derived) == XPRV_SIZE
    assert derived != VALID_ROOT_KEY

def test_derive_path_invalid_root_key():
    invalid_root_key = bytes(XPRV_SIZE)
    try:
        derive_path(invalid_root_key, BIP44_PATH, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid root key" in str(e)

def test_derive_path_invalid_scheme():
    try:
        derive_path(VALID_ROOT_KEY, BIP44_PATH, 99)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

def test_key_gen_address():
    derived = key_gen(VALID_ROOT_KEY, KeyContext.Address, 0, 0, DerivationScheme.Peikert)
    assert len(derived) == XPRV_SIZE

def test_key_gen_identity():
    derived = key_gen(VALID_ROOT_KEY, KeyContext.Identity, 0, 0, DerivationScheme.Peikert)
    assert len(derived) == XPRV_SIZE

def test_key_gen_invalid_root_key():
    invalid_root_key = bytes(XPRV_SIZE)
    try:
        key_gen(invalid_root_key, KeyContext.Address, 0, 0, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid root key" in str(e)

def test_key_gen_invalid_context():
    try:
        key_gen(VALID_ROOT_KEY, 99, 0, 0, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

def test_key_gen_invalid_scheme():
    try:
        key_gen(VALID_ROOT_KEY, KeyContext.Address, 0, 0, 99)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

def test_raw_sign():
    root_key = bytes.fromhex(ROOT_KEY_HEX)
    data = b"Hello World"
    signature = raw_sign(root_key, BIP44_PATH, data, DerivationScheme.Peikert)
    assert len(signature) == 64

def test_raw_sign_invalid_root_key():
    invalid_root_key = bytes(XPRV_SIZE)
    data = b"Hello World"
    try:
        raw_sign(invalid_root_key, BIP44_PATH, data, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid root key" in str(e)

def test_raw_sign_invalid_scheme():
    root_key = bytes.fromhex(ROOT_KEY_HEX)
    data = b"Hello World"
    try:
        raw_sign(root_key, BIP44_PATH, data, 99)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

def test_sign():
    root_key = bytes.fromhex(ROOT_KEY_HEX)
    data = b"Hello World"
    signature = sign(root_key, KeyContext.Address, 0, 0, data, DerivationScheme.Peikert)
    assert len(signature) == 64

def test_sign_invalid_root_key():
    invalid_root_key = bytes(XPRV_SIZE)
    data = b"Hello World"
    try:
        sign(invalid_root_key, KeyContext.Address, 0, 0, data, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid root key" in str(e)

def test_sign_invalid_context():
    root_key = bytes.fromhex(ROOT_KEY_HEX)
    data = b"Hello World"
    try:
        sign(root_key, 99, 0, 0, data, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

def test_sign_invalid_scheme():
    root_key = bytes.fromhex(ROOT_KEY_HEX)
    data = b"Hello World"
    try:
        sign(root_key, KeyContext.Address, 0, 0, data, 99)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

