from simple_certmanager.utils import check_pem


def test_check_pem_checks_directly_issued(leaf_pem, root_ca_path):
    assert check_pem(leaf_pem, ca=root_ca_path)


def test_check_pem_fails_unrooted_pem(leaf_pem):
    assert not check_pem(leaf_pem)


def test_check_pem_checks_chain(chain_pem, root_ca_path):
    assert check_pem(chain_pem, ca=root_ca_path)


def test_check_pem_fails_bad_chain(broken_chain_pem, root_ca_path):
    assert not check_pem(broken_chain_pem, ca=root_ca_path)
