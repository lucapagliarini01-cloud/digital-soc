from .email_body import URL_RE, extract_body


def extract_urls(text):
    """
    Estrae gli URL dall'email.
    - Decodifica il corpo (quoted-printable / base64 / HTML) e prende anche i link <a href>.
    - In più cerca URL in chiaro nel testo incollato (utile se si incolla solo un pezzo).
    Ritorna URL unici nell'ordine di comparsa. Nessun URL viene aperto.
    """
    urls = []
    corpo_ok = False
    try:
        body = extract_body(text)
        urls += body["urls"]
        corpo_ok = body["has_body"]
    except Exception:
        pass
    # Il testo grezzo si scansiona solo se il corpo non è decodificabile (es. incollati solo header o
    # un frammento): nel grezzo quoted-printable gli URL sono spezzati ("...sicurez=") e darebbero IOC falsi.
    if not corpo_ok:
        urls += [u.rstrip(".,;:!?»”'\"=") for u in URL_RE.findall(text or "")]
    seen, unique = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


def extract_domain (url):
    parts = url.split ("//")
    rest = parts [-1]
    parts = rest.split ("/")
    domain = parts [0]
    domain = domain.split("?")[0].split("#")[0]
    if "@" in domain:            # http://utente@host -> host
        domain = domain.rsplit("@", 1)[-1]
    domain = domain.split(":")[0].lower()
    if domain.startswith ("www."):
        domain = domain [4:]
    return domain


def analyze_domain(domain):
    # split domain into parts
    parts = domain.split (".")

    #  tld = last element
    tld = parts [-1]

    #  main_domain = second last element (se esiste)
    main_domain = parts [-2] if len(parts) >= 2 else parts[0]

    # subdomains = all elements befor the main domain
    subdomains = parts [:-2]

    # return a dictionary with the results
    return {
        "tld": tld,
        "main_domain": main_domain,
        "subdomains": subdomains
    }


def extract_subdomains(url):
    """
    Extract subdomains from a given URL.
    Remove protocol, path, 'www' and return only real subdomains.
    """
    # Remove protocol
    clean = url.replace("https://", "").replace("http://", "")

    #remove path (/abc/xyz)
    clean = clean.split("/")[0]

    #Split by dot
    parts = clean.split(".")

    if len(parts) <= 2:
        return []

    subdomains = parts[:-2]

    subdomains = [s for s in subdomains if s.lower() != "www"]

    return subdomains


def unique_domains(urls):
    """Domini unici dagli URL, per non ripetere WHOIS/GeoIP/VT 30 volte sullo stesso dominio."""
    seen, out = set(), []
    for u in urls:
        d = extract_domain(u)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out
