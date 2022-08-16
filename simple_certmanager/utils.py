

def pretty_print_certificate_components(x509name) -> str:
    components = [
        (label.decode("utf-8"), value.decode("utf-8"))
        for (label, value) in x509name.get_components()
    ]
    return ", ".join([f"{label}: {value}" for (label, value) in components])