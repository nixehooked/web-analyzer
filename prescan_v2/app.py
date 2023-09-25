import datetime
from datetime import datetime
import os
from urllib.parse import urlparse

import dns.resolver
import dns.exception
import socket
import shodan
import requests
from googletrans import Translator
import whois
from flask import Flask, request, jsonify
import dkim
from flask_cors import CORS
import ssl
from bs4 import BeautifulSoup as bs
from playwright.sync_api import sync_playwright
import xml.etree.ElementTree as ET

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"], methods=["GET", "POST"], allow_headers=["Content-Type"])

# Clé API Shodan
SHODAN_API_KEY = 'cdngF34tKPzqZMe1zo5scYPCyPShPvwT'

# Clé API NVD
NVD_API_KEY = '4bcc7d06-e7e4-4870-9b05-bcdf517e771a'


def is_valid_domain(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


# Enumération des sous domaines
def subdomains_enum(target, file):
    os.system(f'python subscraper.py {target} -r {file}.txt')

    with open(f'{file}.txt', 'r') as f:
        lines = f.readlines()
        subdomains = [sub.strip() for sub in lines]

    subdomains_info = []

    for subdomain in subdomains:
        subdomain_info = {
            'sous_domaine': subdomain,
            'ip': None
        }

        try:
            # Résoudre l'adresse IP associée au sous-domaine
            ip_address = socket.gethostbyname(subdomain)
            subdomain_info['ip'] = ip_address

        except socket.gaierror:
            pass

        subdomains_info.append(subdomain_info)

    return subdomains_info


# Traduction
def translate_description(description):
    """ Utilise l'API google translate pour traduire les descriptions des CVE de l'API NVD

    Args:
        description: Description retourné par l'API NVD

    Returns:
        _type_: Description traduite
    """
    try:
        translator = Translator(service_urls=['translate.google.com'])
        translation = translator.translate(description, dest='fr')
        if translation.text:
            return translation.text
        else:
            # Si la traduction est vide, renvoyer la description d'origine
            return description
    except Exception as e:
        print("Erreur lors de la traduction :", str(e))
        return description


def is_cname(domain):
    """
    Vérifie si le domaine est un CNAME en utilisant la bibliothèque dns.resolver de Python.
    """
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        return True
    except dns.exception.DNSException:
        return False


def filter_subdomains(subdomains):
    """
    Filtre une liste de sous-domaines pour enlever tous les CNAME.
    """
    return [subdomain for subdomain in subdomains if not is_cname(subdomain)]


def has_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_records = []
        for rdata in answers:
            for txt_string in rdata.strings:
                if b'spf' in txt_string.lower():
                    spf_records.append(txt_string.decode())
        return bool(spf_records), spf_records
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    return False, []


def has_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_records = []
        for rdata in answers:
            for txt_string in rdata.strings:
                if b'v=DMARC1' in txt_string:
                    dmarc_records.append(txt_string.decode())
        return bool(dmarc_records), dmarc_records
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    return False, []


def has_dnssec(domain):
    try:
        answers = dns.resolver.resolve(domain, 'DS')
        ds_records = [answer.to_text() for answer in answers]
        return True, ds_records
    except dns.resolver.NXDOMAIN:
        return False, []
    except dns.resolver.NoAnswer:
        return False, []


# Headers security http -----------------------------------------------------------
user_agent = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0'}


def has_hsts(domain):
    try:
        # Try with HTTPS
        url_https = f"https://{domain}"
        response_https = requests.get(url_https, allow_redirects=True, headers=user_agent)

        if 'Strict-Transport-Security'.lower() in response_https.headers:
            hsts_header = response_https.headers['Strict-Transport-Security']
            return True, hsts_header

    except requests.RequestException as e:
        # If you get exception so try with HTTP
        try:
            url_http = f"http://{domain}"
            response_http = requests.get(url_http, allow_redirects=True, headers=user_agent)

            if 'Strict-Transport-Security'.lower() in response_http.headers:
                hsts_header = response_http.headers['Strict-Transport-Security']
                return True, hsts_header
        except requests.RequestException as e:
            print(f"An error occurred in hsts: {e}")

    return False, None


def has_x_content_type_options(domain):
    # Try with https
    try:
        url_https = f"https://{domain}"
        response_https = requests.get(url_https, allow_redirects=True, headers=user_agent)

        if 'X-Content-Type-Options' in response_https.headers:
            x_content_type_headers = response_https.headers['X-Content-Type-Options']
            if x_content_type_headers == 'nosniff':
                return True, x_content_type_headers
            else:
                return True, 'Not set to nosniff'

    except requests.RequestException as e:
        # If you get an exception so try with HTTP
        try:
            url_http = f"http://{domain}"
            response_http = requests.get(url_http, allow_redirects=True, headers=user_agent)

            if 'X-Content-Type-Options' in response_http.headers:
                x_content_type_headers = response_http.headers['X-Content-Type-Options']
                if x_content_type_headers == 'nosniff':
                    return True, x_content_type_headers
                else:
                    return True, 'Not set to nosniff'
        except requests.RequestException as e:
            print(f"An error occurred in x content type options: {e}")
    return False, None


def has_x_frame_options(domain):
    # Try with HTTPS
    try:
        url_https = f"https://{domain}"
        response_https = requests.get(url_https, allow_redirects=True, headers=user_agent)

        if 'X-Frame-Options' in response_https.headers:
            x_frame_options_headers = response_https.headers['X-Frame-Options']
            return True, x_frame_options_headers

    except requests.RequestException as e:
        # If you get an exception so try with HTTP
        try:
            url_http = f"http://{domain}"
            response_http = requests.get(url_http, allow_redirects=True, headers=user_agent)

            if 'X-Frame-Options' in response_http.headers:
                x_frame_options_headers = response_http.headers['X-Frame-Options']
                return True, x_frame_options_headers
        except requests.RequestException as e:
            print(f"An error occurred in x frame options: {e}")
    return False, None


def has_x_xss_protection(domain):
    # Try with HTTPS
    try:
        url_https = f"https://{domain}"
        response_https = requests.get(url_https, allow_redirects=True, headers=user_agent)

        if 'X-XSS-Protection' in response_https.headers:
            x_xss_protection_header = response_https.headers['X-XSS-Protection']
            if not x_xss_protection_header == "0":
                return True, x_xss_protection_header
            else:
                return False, f"Le header X-XSS-Protection est définit à 0 (Désactivé)"

    except requests.RequestException as e:
        # If you get an exception so try with HTTP
        try:
            url_http = f"http://{domain}"
            response_http = requests.get(url_http, allow_redirects=True, headers=user_agent)

            if 'X-XSS-Protection' in response_http.headers:
                x_xss_protection_header = response_http.headers['X-XSS-Protection']
                if not x_xss_protection_header == "0":
                    return True, x_xss_protection_header
                else:
                    return False, f"Le header X-XSS-Protection est définit à 0 (Désactivé)"
        except requests.RequestException as e:
            print(f"An error occurred in x xss protection: {e}")
    return False, None


def has_CSP(domain):
    try:
        url_https = f"https://{domain}"
        response_https = requests.get(url_https, allow_redirects=True)

        if 'Content-Security-Policy' in response_https.headers:
            csp_header = response_https.headers['Content-Security-Policy']

            # Vérifier si la CSP désactive l'usage du JavaScript inline (unsafe-inline)
            if "'unsafe-inline'" not in csp_header:
                # Vérifier si la CSP utilise default-src https:
                if "'default-src' https:" in csp_header:
                    # Vérifier si la CSP inclut report-uri
                    if "'report-uri'" in csp_header:
                        return True, csp_header

        return False, f"Content Security Policy (CSP) est mis en œuvre de manière dangereuse: {response_https.headers['Content-Security-Policy']}"

    except requests.RequestException as e_https:
        print(f"Une erreur de requête HTTPS s'est produite : {e_https}")

        try:
            # En cas d'échec avec HTTPS, réessayez avec HTTP
            url_http = f"http://{domain}"
            response_http = requests.get(url_http, allow_redirects=True)

            if 'Content-Security-Policy' in response_http.headers:
                csp_header = response_http.headers['Content-Security-Policy']

                # Vérifier si la CSP désactive l'usage du JavaScript inline (unsafe-inline)
                if "'unsafe-inline'" not in csp_header:
                    # Vérifier si la CSP utilise default-src https:
                    if "'default-src' https:" in csp_header:
                        # Vérifier si la CSP inclut report-uri
                        if "'report-uri'" in csp_header:
                            return True, csp_header

            return False, "Content Security Policy (CSP) est mis en œuvre de manière dangereuse."

        except requests.RequestException as e_http:
            print(f"Une erreur de requête HTTP s'est produite : {e_http}")
        except Exception as e_http:
            print(f"Une erreur s'est produite avec HTTP : {e_http}")

    except Exception as e_https:
        print(f"Une erreur s'est produite avec HTTPS : {e_https}")

    return False, None


def get_cookies_details(domain):
    cookie_details = {}

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        try:
            url_https = f"https://{domain}"
            page.goto(url_https)

            cookies = page.context.cookies()
            domain = urlparse(url_https).hostname

        except Exception as e_https:
            print(f"Une erreur s'est produite avec HTTPS : {e_https}")

            try:
                url_http = f"http://{domain}"
                page.goto(url_http)

                cookies = page.context.cookies()
                domain = urlparse(url_http).hostname

            except Exception as e_http:
                print(f"Une erreur s'est produite avec HTTP : {e_http}")

        browser.close()

        if cookies:
            for cookie in cookies:
                # Filtrer les cookies par domaine d'origine
                if cookie['expires'] == -1:
                    cookie['expires'] = 'Session'
                if domain in cookie['domain']:
                    cookie_name = cookie['name']
                    cookie_details[cookie_name] = {
                        'Value': cookie['value'],
                        'Expire': cookie['expires'],
                        'Path': cookie['path'],
                        'Secure': cookie['secure'],
                        'HttpOnly': cookie['httpOnly'],
                        'SameSite': cookie['sameSite']
                    }

    return cookie_details


def has_cors(domain):
    try:
        # Essayez d'abord avec HTTPS
        url_https = f"https://{domain}"
        response_https = requests.get(url_https, allow_redirects=True, headers=user_agent)

        # Vérifiez la présence de l'en-tête CORS
        if 'Access-Control-Allow-Origin' in response_https.headers:
            cors_header = response_https.headers['Access-Control-Allow-Origin']

            # Si l'en-tête est présent mais restreint à des domaines spécifiques,
            # recherchez les fichiers de politique de sécurité.
            if cors_header != '*' and cors_header != 'null':
                cors_result = analyze_crossdomain_xml(url_https)
                if cors_result:
                    return True, cors_result

            return True, f"Le contenu est visible via le partage de ressources cross-origin (CORS) mais n'est pas restreint: {response_https.headers['Access-Control-Allow-Origin']}"

    except requests.RequestException as e_https:
        try:
            # Si HTTPS échoue, réessayez avec HTTP
            url_http = f"http://{domain}"
            response_http = requests.get(url_http, allow_redirects=True)

            # Vérifiez la présence de l'en-tête CORS
            if 'Access-Control-Allow-Origin' in response_http.headers:
                cors_header = response_http.headers['Access-Control-Allow-Origin']

                # Si l'en-tête est présent mais restreint à des domaines spécifiques,
                # recherchez les fichiers de politique de sécurité.
                if cors_header != '*' and cors_header != 'null':
                    cors_result = analyze_crossdomain_xml(url_http)
                    if cors_result:
                        return True, cors_result

                return True, f"Le contenu est visible via le partage de ressources cross-origin (CORS) mais n'est pas restreint: {response_http.headers['Access-Control-Allow-Origin']}"

        except requests.RequestException as e_http:
            print(f"Une erreur de requête HTTP s'est produite : {e_http}")

    except Exception as e_https:
        print(f"Une erreur s'est produite avec HTTPS : {e_https}")

    return False, "CORS n'est pas configuré ou est mal configuré."


def analyze_crossdomain_xml(url):
    try:
        crossdomain_url = f"{url}/crossdomain.xml"
        response = requests.get(crossdomain_url)
        if response.status_code == 200:
            # Analysez le contenu du fichier crossdomain.xml ici.
            # Vous pouvez utiliser ElementTree pour analyser le XML.
            root = ET.fromstring(response.text)
            # Effectuez des vérifications pour déterminer si l'accès est restreint.
            # Par exemple, vérifiez les éléments <allow-access-from> dans le XML.
            allow_access_from_elements = root.findall(".//allow-access-from")
            if allow_access_from_elements:
                return "Content is visible via CORS, but access is restricted to specific domains."
        else:
            return None
    except requests.RequestException as e:
        print(f"Une erreur de requête s'est produite : {e}")
        return None


def has_HPKP(domain):
    try:
        url_https = f"https://{domain}"
        response_https = requests.get(url_https, allow_redirects=True)

        if 'Public-Key-Pins' in response_https.headers or 'Public-Key-Pins-Report-Only' in response_https.headers:
            hpkp_header = response_https.headers.get('Public-Key-Pins', '') or response_https.headers.get(
                'Public-Key-Pins-Report-Only', '')
            return True, hpkp_header

    except requests.RequestException as e:
        # Si vous obtenez une exception, essayez avec HTTP
        try:
            url_http = f"http://{domain}"
            response_http = requests.get(url_http, allow_redirects=True)

            if 'Public-Key-Pins' in response_http.headers or 'Public-Key-Pins-Report-Only' in response_http.headers:
                hpkp_header = response_http.headers.get('Public-Key-Pins', '') or response_http.headers.get(
                    'Public-Key-Pins-Report-Only', '')
                return True, hpkp_header
        except requests.RequestException as e:
            print(f"An error occurred in HPKP: {e}")

    return False, "En-tête HTTP Public Key Pinning (HPKP) non implémenté (facultatif)"


def has_redirection(domain):
    try:
        url_http = f"http://{domain}"
        response_http = requests.head(url_http, headers=user_agent)
        if response_http.status_code in (301, 302, 303, 307):
            if 'Location' in response_http.headers:
                redirection_url = response_http.headers['Location']
                return True, f"La destination finale est {redirection_url}"
    except requests.RequestException as e:
        print(f"An error occurred in Redirection: {e}")

    return False, None


def has_referrer_policy(domain):
    # Try with HTTPS
    try:
        url_https = f"https://{domain}"
        response_https = requests.get(url_https, allow_redirects=True, headers=user_agent)

        if 'Referrer-Policy' in response_https.headers:
            referrer_policy_header = response_https.headers['Referrer-Policy']
            if 'no-referrer' or 'same-origin' or 'strict-origin' or 'strict-origin-when-cross-origin' in referrer_policy_header:
                return True, referrer_policy_header

    except requests.RequestException as e:
        # If you get exception so try with HTTP
        try:
            url_http = f"http://{domain}"
            response_http = requests.get(url_http, allow_redirects=True, headers=user_agent)

            if 'Referrer-Policy' in response_http.headers:
                referrer_policy_header = response_http.headers['Referrer-Policy']
                if 'no-referrer' or 'same-origin' or 'strict-origin' or 'strict-origin-when-cross-origin' in referrer_policy_header:
                    return True, f"En-tête Referrer-Policy défini sur {referrer_policy_header}"
        except requests.RequestException as e:
            print(f"An error occurred in referrer policy: {e}")

    return False, None


def has_subresource_integrity(domain):
    try:
        url = f"https://{domain}"
        response = requests.get(url)
        response.raise_for_status()

        # Analyser le contenu HTML de la page
        soup = bs(response.text, 'html.parser')

        # Rechercher les balises <script> et <link> avec un attribut 'integrity'
        script_tags = soup.find_all('script', integrity=True)
        link_tags = soup.find_all('link', integrity=True)

        # Vérifier si des balises avec 'integrity' ont été trouvées
        if script_tags or link_tags:
            return True
        else:
            return False

    except requests.RequestException as e:
        try:
            url = f"http://{domain}"
            response = requests.get(url)
            response.raise_for_status()

            # Analyser le contenu HTML de la page
            soup = bs(response.text, 'html.parser')

            # Recherche les balises <script> et <link> avec un attribut 'integrity'
            script_tags = soup.find_all('script', integrity=True)
            link_tags = soup.find_all('link', integrity=True)

            # Vérifier si des balises avec 'integrity' ont été trouvées
            if script_tags or link_tags:
                return True
            else:
                return False
        except requests.RequestException as e:
            print(f"An error occurred in subressource integrity: {e}")
    except Exception as e:
        print(f"An error occurred : {e}")

    return False


# End check headers HTTP -----------------------------------------------------------

def has_dkim(domain):
    try:
        answers = dns.resolver.resolve(f"_domainkey.{domain}", 'TXT')
        dkim_records = []
        for rdata in answers:
            for txt_string in rdata.strings:
                txt_record = txt_string.decode()
                if b'adsp=none' not in txt_string:
                    dkim_records.append(txt_record)
                else:
                    try:
                        domainkey = dkim.DomainKeySet(txt_record, b"_domainkey")
                        domainkey.verify(txt_record)
                        dkim_records.append(txt_record)
                    except dkim.ValidationError:
                        pass

        return bool(dkim_records), dkim_records
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    return False, []


def has_security_txt(domain):
    try:
        url_https = f"https://{domain}/.well-known/security.txt"
        response_https = requests.get(url_https)

        if response_https.status_code == 200 and "Contact:" in response_https.text:
            return True, response_https.text

    except requests.RequestException as e:
        try:
            url_http = f"http://{domain}/.well-known/security.txt"
            response_http = requests.get(url_http)

            if response_http.status_code == 200 and "Contact:" in response_http.text:
                return True, response_http.text
        except requests.RequestException as e:
            print(f"An error occurred in security_txt: {e}")

    return False, None


# Fonction pour récupérer les détails d'une CVE à partir de l'API NVD
def get_cve_details(cve_id):
    """_summary_

    Args:
        cve_id (_type_): Nom de la CVE

    Returns:
        _type_: Description traduite et le score CVSS
    """
    url = f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}'
    headers = {'api_key': NVD_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        cve_items = data.get('result', {}).get('CVE_Items', [])
        if cve_items:
            cve_details = cve_items[0]['cve']['description']['description_data'][0]['value']
            translated_description = translate_description(cve_details)
            # Récupérer le score CVSSv3 s'il est disponible
            cvss_v3 = cve_items[0]['impact'].get('baseMetricV3')

            # Récupérer le score CVSSv2 s'il existe et CVSSv3 n'est pas disponible
            if cvss_v3 is None:
                cvss_v2 = cve_items[0]['impact'].get('baseMetricV2')
                if cvss_v2 is not None:
                    cvss_score = cvss_v2.get('cvssV2', {}).get('baseScore')

            # Si le score CVSSv3 est disponible, récupérer le score CVSSv3
            if cvss_v3 is not None:
                cvss_score = cvss_v3.get('cvssV3', {}).get('baseScore')
            return translated_description, cvss_score
        else:
            return 'Détails indisponibles', None, 'null'
    else:
        return 'Détails indisponibles', None


# Fonction pour obtenir le niveau de criticité en fonction du score CVSS
def get_criticite(score_cvss):
    """
    Retourne un niveau de criticité selon le score CVSS
    """
    if score_cvss is not None:
        if score_cvss >= 9.0:
            return "Critique"
        elif score_cvss >= 7.0:
            return "Élevée"
        elif score_cvss >= 4.0:
            return "Moyenne"
        else:
            return "Faible"
    else:
        return "Inconnue"


def verify_tls_certificate(domain):
    port = 443  # Port par défaut pour HTTPS
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_before = cert['notBefore']
                not_after = cert['notAfter']
                not_before_dt = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                not_after_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                current_dt = datetime.utcnow()
                days_remaining = (not_after_dt - current_dt).days

                return {
                    'certificate': cert,
                    'current_time': current_dt,
                    'days_remaining': days_remaining
                }
    except ssl.SSLError as e:
        return {
            'error': f"SSL Error: {e}"
        }
    except socket.error as e:
        return {
            'error': f"Connection Error: {e}"
        }


def get_domain_expiration(domain):
    try:
        domain_info = whois.whois(domain)
        expiration_date = domain_info.expiration_date

        if expiration_date:
            if isinstance(expiration_date, list):
                # Si c'est une liste, on prend le premier élément
                expiration_date = expiration_date[0]

            if isinstance(expiration_date, (datetime, str)):
                # Si c'est un objet datetime ou une chaîne, on le formate
                if isinstance(expiration_date, datetime):
                    expiration_date = expiration_date.strftime('%d-%m-%Y')
            else:
                # Si ce n'est ni un objet datetime ni une chaîne, on considère qu'il est indisponible
                expiration_date = "Non disponible"

        else:
            expiration_date = "Non disponible"

        return expiration_date

    except Exception as e:
        print("Erreur lors de la récupération de la date d'expiration du domaine :", str(e))
        return "Non disponible"


@app.route('/whois', methods=['POST'])
def whois_analysis():
    data = request.get_json()
    target = data.get('cible')

    if not target or not is_valid_domain(target):
        return jsonify({'erreur': 'Le champ cible est invalide ou manquant'}), 400

    try:
        domain_info = whois.whois(target)
        registrar = domain_info.registrar if domain_info.registrar else "Non disponible"
        org = domain_info.org if domain_info.org else "Non disponible"
        country = domain_info.country if domain_info.country else "Non disponible"
        city = domain_info.city if domain_info.city else "Non disponible"
        name = domain_info.name if domain_info.name else "Non disponible"
        phone = domain_info.phone if domain_info.phone else "Non disponible"
        domain_expiration = get_domain_expiration(target)

        results = {
            'Registrar': registrar,
            'Org': org,
            'City': city,
            'Country': country,
            'Name': name,
            'Phone': phone,
            'domain_expiration': domain_expiration
        }

        return jsonify(results)
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500


@app.route('/mail-security', methods=['POST'])
def mail_security_check():
    data = request.get_json()
    target = data.get('cible')

    if not target or not is_valid_domain(target):
        return jsonify({'erreur': 'Le champ cible est invalide ou manquant'}), 400

    try:
        has_dkim_flag, dkim_txt = has_dkim(target)
        has_spf_flag, spf_txt = has_spf(target)
        has_dmarc_flag, dmarc_txt = has_dmarc(target)

        results = {
            'DKIM': has_dkim_flag,  # Return True if present or False if not
            'DKIM_TXT': dkim_txt,
            'SPF': has_spf_flag,  # Return True if present or False if not
            'SPF_TXT': spf_txt,
            'DMARC': has_dmarc_flag,  # Return True if present or False if not
            'DMARC_TXT': dmarc_txt
        }

        return jsonify(results)
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500


@app.route('/tls', methods=['POST'])
def check_tls():
    data = request.get_json()
    target = data.get('cible')

    if not target or not is_valid_domain(target):
        return jsonify({'erreur': 'Le champ cible est invalide ou manquant'}), 400

    try:
        check_tls = verify_tls_certificate(target)

        results = {
            'TLS': check_tls
        }

        return jsonify(results)
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500


@app.route('/security-txt', methods=['POST'])
def check_security_txt():
    data = request.get_json()
    target = data.get('cible')

    if not target or not is_valid_domain(target):
        return jsonify({'erreur': 'Le champ cible est invalide ou manquant'}), 400

    try:
        has_securitytxt = has_security_txt(target)

        results = {
            'Security-TXT': has_securitytxt
        }

        return jsonify(results)
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500


@app.route('/dnssec', methods=['POST'])
def check_dnssec():
    data = request.get_json()
    target = data.get('cible')

    if not target or not is_valid_domain(target):
        return jsonify({'erreur': 'Le champ cible est invalide ou manquant'}), 400

    try:
        dnssec = has_dnssec(target)

        results = {
            'DNSSEC': dnssec
        }

        return jsonify(results)
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500


@app.route('/security-headers', methods=['POST'])
def check_hsts():
    data = request.get_json()
    target = data.get('cible')

    if not target or not is_valid_domain(target):
        return jsonify({'erreur': 'Le champ cible est invalide ou manquant'}), 400

    try:
        hsts = has_hsts(target)
        csp = has_CSP(target)
        cookie = get_cookies_details(target)
        cors = has_cors(target)
        hpkpk = has_HPKP(target)
        redirection = has_redirection(target)
        referrer_policy = has_referrer_policy(target)
        subresource_integrity = has_subresource_integrity(target)
        x_content_type_options = has_x_content_type_options(target)
        x_frame_options = has_x_frame_options(target)
        x_xss_protection = has_x_xss_protection(target)

        results = {
            'HTTP Strict Transport Security': hsts,
            'Content-Security-Policy': csp,
            'Cookie': cookie,
            'Cross-origin Resource Sharing': cors,
            'HTTP Public Key Pinning': hpkpk,
            'HTTP Redirections': redirection,
            'Referrer Policy': referrer_policy,
            'Subresource Integrity': subresource_integrity,
            'X-Content-Type-Options': x_content_type_options,
            'X-Frame-Options': x_frame_options,
            'X-XSS-Protection': x_xss_protection
        }

        return jsonify(results)
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500


@app.route('/subdomains', methods=['POST'])
def check_subdomains():
    data = request.get_json()
    target = data.get('cible')

    if not target or not is_valid_domain(target):
        return jsonify({'erreur': 'Le champ cible est invalide ou manquant'}), 400

    try:
        subdomains = subdomains_enum(target, target)

        results = {
            'Subdomains': subdomains
        }
        return jsonify(results)
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500


@app.route('/analyser', methods=["POST"])
def analyser_cible():
    data = request.get_json()
    target = data.get("cible")

    if not target or not is_valid_domain(target):
        return jsonify({'erreur': 'Le domaine est manquant ou invalide'}), 400

    # Connexion à l'API Shodan
    api = shodan.Shodan(SHODAN_API_KEY)

    resultats = {
        'domaine_cible': target,
        'details': {}
    }

    try:
        # Résolution de l'adresse IP à partir du nom de domaine cible
        ip = socket.gethostbyname(target)

        # Recherche des informations sur l'adresse IP
        resultats_ip = api.host(ip)
        data = resultats_ip['data']

        ports = []
        ip_vulns = []  # Liste pour stocker les vulnérabilités uniques pour cette IP

        for service in data:
            cve_details = []
            if 'name' in service:
                service_name = service['name']
            elif 'product' in service:
                service_name = service['product']
            else:
                service_name = "Non reconnu"
            if 'vulns' in service:
                vulns = service['vulns']
                for vuln in vulns:
                    cve, cvss_score = get_cve_details(vuln)
                    criticite = get_criticite(cvss_score)
                    if cvss_score is not None:  # Vérifier si le score CVSS est None
                        cve_details.append({
                            'CVE': vuln,
                            'Description': cve,
                            'Score CVSS': cvss_score,
                            'Criticité': criticite
                        })
                    # Ajout de la vulnérabilité à la liste d'IP (si elle n'existe pas déjà)
                    if cve not in ip_vulns:
                        ip_vulns.append(cve)

            ports.append({
                'Port': service['port'],
                'Service': service_name,
                'Vulnérabilités': cve_details
            })

        ip_details = {
            'Domaine': target,
            'Ports ouverts': ports
        }

        resultats['details'][ip] = ip_details

    except shodan.APIError as e:
        print('Erreur lors de la recherche de', ip, ':', e)
    except Exception as e:
        return jsonify({'erreur': str(e)}), 500

    # Calcul de la note globale
    vuln_critical = 0
    vuln_high = 0
    vuln_medium = 0
    vuln_low = 0
    vuln_major = 0
    vuln_minor = 0

    for port_info in resultats['details'][ip]['Ports ouverts']:
        cve_details = port_info['Vulnérabilités']
        for cve in cve_details:
            if isinstance(cve, dict):
                cvss_score = cve.get('Score CVSS')
                if cvss_score is not None and isinstance(cvss_score, (float, int)):
                    cvss_score_float = float(cvss_score)
                    criticite = get_criticite(cvss_score_float)

                    cve['Criticité'] = criticite  # Ajout de la criticité dans le dictionnaire CVE

                    if criticite == 'Critique' or criticite == 'Élevée':
                        if criticite == 'Critique':
                            vuln_critical += 1
                        elif criticite == 'Élevée':
                            vuln_high += 1
                        vuln_major += 1
                    elif criticite == 'Moyenne' or criticite == 'Faible':
                        if criticite == 'Moyenne':
                            vuln_medium += 1
                        elif criticite == 'Faible':
                            vuln_low += 1
                        vuln_minor += 1

    vuln_total = vuln_major + vuln_minor

    # Détermination de la note globale en fonction du nombre de vulnérabilités
    if vuln_major == 0 and vuln_minor <= 4:
        note_globale = "A+"
    elif vuln_major <= 2 and vuln_minor <= 8 and vuln_total <= 10:
        note_globale = "A"
    elif vuln_major <= 4 and vuln_minor <= 12 and vuln_total <= 15:
        note_globale = "B"
    elif vuln_major <= 6 and vuln_minor <= 16 and vuln_total <= 20:
        note_globale = "C"
    else:
        note_globale = "D"

    resultats['note_globale'] = note_globale

    return jsonify(resultats)


if __name__ == '__main__':
    app.run(host='0.0.0.0')
