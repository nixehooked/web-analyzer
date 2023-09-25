import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useLocation, Link } from 'react-router-dom';
import { Card } from 'react-bootstrap';
import '../Styles/Results.css';
import logo from '../WS_LOGO_BLANC.svg';
import logoLoading from '../WS_ICONE.svg';
import { format } from 'date-fns';
import '@fortawesome/fontawesome-svg-core/styles.css';
import IconWithTooltip from '../Components/IconWithTooltip';
import WarningPortWithTooltip from '../Components/WarningPortWithTooltip';
import calculateScore from '../Components/calculateScore';

const Results = () => {
    const location = useLocation();
    const searchParams = new URLSearchParams(location.search);
    const domain = searchParams.get('cible');
    const [subdomainsResult, setSubdomainsResult] = useState([]);
    const [analyserResult, setAnalyserResult] = useState({});
    const [analyserNoteResult, setAnalyserNoteResult] = useState({});
    const [securityTxtResult, setSecurityTxtResult] = useState({});
    const [mailSecurityResult, setMailSecurityResult] = useState({});
    const [tlsInfo, setTlsInfo] = useState(null);
    const [whoisResult, setWhoisResult] = useState({});
    const [dnssecResult, setDnssecResult] = useState({});
    const [headersResult, setHeadersResult] = useState({});
    const [isLoading, setIsLoading] = useState(true);
    const [showMoreSubdomains, setShowMoreSubdomains] = useState(false);
    const [loading, setLoading] = useState(true);
    const [apiError, setApiError] = useState('');
    const [finalGrade, setFinalGrade] = useState('');
    const [showMoreVulnerabilities, setShowMoreVulnerabilities] = useState(false);

    const handleShowMoreVulnerabilities = () => {
        setShowMoreVulnerabilities(!showMoreVulnerabilities);
    };

    const headersInfo = {
        "Content-Security-Policy": "La stratégie de sécurité du contenu (CSP) peut empêcher un large éventail d'attaques de script inter-sites (XSS) et de détournement de clic contre votre site Web.",
        "Cookie": "L'utilisation d'attributs de cookies tels que Secure et HttpOnly peut protéger les utilisateurs contre le vol de leurs informations personnelles.",
        "Cross-origin Resource Sharing": "Des paramètres CORS mal configurés peuvent permettre à des sites étrangers de lire le contenu de votre site, ce qui peut leur permettre d'accéder aux informations privées des utilisateurs.",
        "HTTP Public Key Pinning": "L'épinglage de clé publique HTTP (HPKP) lie un site à une combinaison spécifique d'autorités de certification et/ou de clés, protégeant ainsi contre l'émission non autorisée de certificats.",
        "HTTP Strict Transport Security": "HTTP Strict Transport Security (HSTS) indique aux navigateurs Web de visiter votre site uniquement via HTTPS.",
        "HTTP Redirections": "Des redirections correctement configurées de HTTP vers HTTPS permettent aux navigateurs d'appliquer correctement les paramètres HTTP Strict Transport Security (HSTS).",
        "Referrer Policy": "Referrer Policy peut protéger la vie privée de vos utilisateurs en limitant le contenu de l'en-tête HTTP Referer.",
        "Subresource Integrity": "L'intégrité des sous-ressources protège contre la modification malveillante des fichiers JavaScript et des feuilles de style stockés sur les réseaux de diffusion de contenu (CDN).",
        "X-Content-Type-Options": "X-Content-Type-Options indique aux navigateurs de ne pas deviner les types MIME de fichiers fournis par le serveur Web.",
        "X-Frame-Options": "X-Frame-Options contrôle si votre site peut être encadré, protégeant ainsi contre les attaques de détournement de clic. Il a été remplacé par la directive frame-ancestors de Content Security Policy, mais devrait toujours être utilisé pour le moment.",
        "X-XSS-Protection": "X-XSS-Protection protège contre les attaques XSS (Cross-Site Scripting) réfléchies dans IE et Chrome, mais a été remplacé par la politique de sécurité du contenu. Il peut toujours être utilisé pour protéger les utilisateurs d'anciens navigateurs Web."
    };

    const portsInfo = {
        23: "Exposer le port 23 peut être dangereux car il est associé au protocole Telnet, qui transmet les données en texte clair. Cela peut permettre à des attaquants de capturer des informations sensibles comme les identifiants et mots de passe. Il est recommandé de sécuriser ou de désactiver le port 23 pour prévenir les risques de compromission de sécurité.",
        88: "Le port 88 est souvent utilisé pour le service Kerberos, qui gère l'authentification au sein d'un réseau. Exposer ce port peut potentiellement exposer des informations d'identification sensibles. Il est recommandé de le sécuriser ou de le restreindre pour éviter tout accès non autorisé.",
        3389: "Le port 3389 est associé au service RDP (Remote Desktop Protocol) qui permet l'accès distant au bureau d'un ordinateur. Exposer ce port sans les mesures de sécurité appropriées peut ouvrir la porte à des attaques d'intrusion. Il est crucial de le protéger et de limiter son accès uniquement aux utilisateurs autorisés.",
        21: "Le port 21 est utilisé pour les connexions FTP (File Transfer Protocol). L'exposition de ce port peut entraîner des risques de fuite de données sensibles ou d'accès non autorisé à votre serveur. Il est recommandé de restreindre l'accès à ce port et d'utiliser des méthodes sécurisées pour les transferts de fichiers.",
        22: "Le port 22 est associé aux connexions SSH (Secure Shell), un protocole de communication sécurisé. Exposer ce port peut potentiellement donner accès à des tiers non autorisés à votre système. Il est crucial de mettre en place des mesures de sécurité robustes et de surveiller activement l'activité sur ce port pour éviter les intrusions.",
        3306: "Le port 3306 est utilisé pour les connexions MySQL, une base de données relationnelle populaire. Exposer ce port sans protection adéquate peut permettre à des individus non autorisés d'accéder à vos données sensibles. Il est impératif de mettre en place des mesures de sécurité telles que des pare-feux et des mécanismes d'authentification robustes.",
        5432: "Le port 5432 est associé à PostgreSQL, un système de gestion de base de données relationnelle avancé. Exposer ce port sans protection appropriée peut entraîner un accès non autorisé à vos données sensibles. Il est crucial de mettre en place des mesures de sécurité telles que des pare-feux et des mécanismes d'authentification solides pour éviter tout risque.",
        8080: "Le port 8080 est souvent utilisé pour accéder à des serveurs web, mais peut également être utilisé par d'autres services. Exposer ce port sans protection adéquate peut potentiellement ouvrir une porte d'entrée pour les attaquants. Il est impératif de mettre en œuvre des mesures de sécurité telles que des pare-feux, des mots de passe forts et des mécanismes d'authentification pour protéger vos services.",
        8443: "Le port 8443 est couramment utilisé pour sécuriser les communications web à l'aide du protocole HTTPS. Exposer ce port sans protection appropriée peut mettre en péril la sécurité de vos données sensibles. Il est crucial de mettre en place des mesures de sécurité robustes, telles que des certificats SSL/TLS valides et des politiques de sécurité web strictes, pour garantir une protection efficace contre les menaces en ligne.",
        25: "Le port 25 est réservé à la communication SMTP, utilisée pour l'envoi de courriers électroniques. Exposer ce port sans les bonnes protections peut ouvrir la porte à des attaques de spam, de phishing et d'autres menaces liées aux e-mails. Il est essentiel de mettre en place des filtres anti-spam et des mécanismes d'authentification solides pour préserver l'intégrité de votre service de messagerie et éviter toute utilisation abusive.",
        587: "Le port 587 est souvent utilisé pour la communication SMTP avec authentification. Exposer ce port sans les bonnes mesures de sécurité peut entraîner des risques tels que l'envoi de courriers indésirables (spam) ou des tentatives de piratage de comptes e-mail. Il est crucial de mettre en place des mécanismes d'authentification robustes et des filtres anti-spam pour protéger vos services de messagerie contre les menaces potentielles.",
        8090: "Le port 8090 est souvent associé à des serveurs web ou des applications qui utilisent des connexions non sécurisées. Exposer ce port peut créer une vulnérabilité dans votre système, car il est plus susceptible d'être ciblé par des attaques. Assurez-vous d'appliquer des mesures de sécurité appropriées, telles que le chiffrement SSL/TLS, pour protéger les données transitant par ce port.",
        8000: "Le port 8000 est couramment utilisé pour le développement et les tests de serveurs web. Cependant, l'exposer publiquement sur Internet sans une configuration de sécurité adéquate peut constituer un risque. Les pirates informatiques recherchent souvent des serveurs mal configurés sur ce port pour exploiter des vulnérabilités. Il est recommandé de restreindre l'accès à ce port et de mettre en place des mesures de sécurité appropriées pour prévenir les attaques non autorisées."
    }

    function convertScoreToGrade(score) {
        if (score >= 0.9 * 375) {
            return 'A+';
        } else if (score >= 0.8 * 375 && score < 0.9 * 375) {
            return 'A';
        } else if (score >= 0.6 * 375 && score < 0.7 * 375) {
            return 'B';
        } else if (score >= 0.2 * 375 && score < 0.5 * 375) {
            return 'C';
        } else {
            return 'D';
        }
    }

    useEffect(() => {
        const fetchData = async () => {
            try {
                await Promise.all([
                    fetchSubdomains(),
                    fetchAnalyser(),
                    fetchTlsInfo(),
                    fetchSecurityTxt(),
                    fetchMailSecurity(),
                    fetchWhois(),
                    fetchDnssec(),
                    fetchHeaders()
                ]);
                const finalScore = calculateScore();
                console.log(finalScore)
                setFinalGrade(convertScoreToGrade(finalScore));
                setIsLoading(false);
                setLoading(false);
            } catch (error) {
                console.error('Erreur lors de la requête API:', error);
                setApiError('Le domaine fourni est invalide.'); // Set the error message
                setIsLoading(false);
            }
        };

        const fetchSubdomains = async () => {
            const response = await axios.post('http://localhost:5000/subdomains', { cible: domain });
            setSubdomainsResult(response.data.Subdomains);
        };

        const fetchTlsInfo = async () => {
            const response = await axios.post('http://localhost:5000/tls', { cible: domain });
            setTlsInfo(response.data.TLS);
        };

        const fetchAnalyser = async () => {
            const response = await axios.post('http://localhost:5000/analyser', { cible: domain });
            setAnalyserResult(response.data.details);
            setAnalyserNoteResult(response.data);
        };

        const fetchSecurityTxt = async () => {
            const response = await axios.post('http://localhost:5000/security-txt', { cible: domain });
            setSecurityTxtResult(response.data['Security-TXT']);
        };

        const fetchMailSecurity = async () => {
            const response = await axios.post('http://localhost:5000/mail-security', { cible: domain });
            setMailSecurityResult(response.data);
        };

        const fetchWhois = async () => {
            const response = await axios.post('http://localhost:5000/whois', { cible: domain });
            setWhoisResult(response.data);
        };

        const fetchDnssec = async () => {
            const response = await axios.post('http://localhost:5000/dnssec', { cible: domain });
            setDnssecResult(response.data.DNSSEC);
        };

        const fetchHeaders = async () => {
            const response = await axios.post('http://localhost:5000/security-headers', { cible: domain });
            setHeadersResult(response.data);
        };

        if (domain) {
            fetchData();
        }
    }, [domain]);

    const formatDate = (dateString) => {
        const date = new Date(dateString);
        return format(date, 'dd/MM/yyyy HH:mm:ss');
    };

    return (
        <div>
            <div className="header">
                <div className="logo-container">
                    <img src={logo} alt="Logo" className="logo" />
                </div>
                <h1>Note globale pour le domaine {domain} : <span className="noteGlobal">{finalGrade}</span> <IconWithTooltip text="Cette note est attribuée de manière temporaire et est liée aux différents services découverts et/ou manquants" /></h1>
                <p className="note_shodan" style={{ display: 'none' }}>{analyserNoteResult.note_globale}</p>
            </div>

            {apiError && (
                <div className="error-message">
                    {apiError}
                    <br />
                    <Link to="/" className="home-link">Revenir à la page d'accueil</Link>
                </div>
            )}

            <div className="card-container">
                <div className="loading-container">
                    <div className="timeline" style={{ opacity: loading ? 1 : 0 }}>
                        <p className="timeline-text">Analyse en cours...</p>
                        <div className="logo-pulsating-container">
                            <img src={logoLoading} alt="Logo Loading" className="logo-pulsating" />
                        </div>
                    </div>
                </div>
                {subdomainsResult && (
                    <Card>
                        <Card.Body>
                            <Card.Title><h3>Enumération des sous-domaines <span><IconWithTooltip text="L'énumération des sous-domaines est essentielle pour identifier toutes les entrées associées à un domaine principal. Cela permet de détecter d'éventuelles vulnérabilités ou points d'accès non autorisés. Sans cette information, des parties du domaine pourraient rester non surveillées, créant ainsi des risques potentiels pour la sécurité de votre infrastructure web." /></span></h3></Card.Title>
                            <ul>
                                {showMoreSubdomains
                                    ? subdomainsResult.map((subdomain, index) => (
                                        <li key={index}>{subdomain.sous_domaine}</li>
                                    ))
                                    : subdomainsResult.slice(0, 5).map((subdomain, index) => (
                                        <li key={index}>{subdomain.sous_domaine}</li>
                                    ))}
                            </ul>
                            {subdomainsResult.length > 5 && (
                                <button
                                    className="show-more-button"
                                    onClick={() => setShowMoreSubdomains(!showMoreSubdomains)}
                                >
                                    {showMoreSubdomains ? 'Afficher moins' : 'Afficher plus'}
                                </button>
                            )}
                        </Card.Body>
                    </Card>
                )}

                {tlsInfo && tlsInfo.certificate ? (
                    <Card>
                        <Card.Body>
                            <Card.Title><h3>Informations du certificat TLS <span><IconWithTooltip text="Le certificat TLS (Transport Layer Security) garantit la confidentialité et l'intégrité des données échangées entre votre navigateur et le serveur. Il contient des informations sur l'émetteur, la période de validité et d'autres détails essentiels. Vérifier ces données vous permet de vous assurer que la communication avec le serveur est sécurisée et qu'aucune tentative d'interception n'est en cours." /></span></h3></Card.Title>
                            <div>
                                <p><strong>Emetteur</strong>: {tlsInfo.certificate.issuer[1][0][1]}</p>
                                <p><strong>Sujet</strong>: {tlsInfo.certificate.subject[0][0][1]}</p>
                                <p><strong>Valide jusqu'au</strong>: {formatDate(tlsInfo.certificate.notAfter)}</p>
                                <p><strong>Valide à partir de</strong>: {formatDate(tlsInfo.certificate.notBefore)}</p>
                                <p><strong>Numéro de série</strong>: {tlsInfo.certificate.serialNumber}</p>
                                <p><strong>Version</strong>: {tlsInfo.certificate.version}</p>
                                {tlsInfo.days_remaining !== undefined && (
                                    <p><strong>Jours de validité restants du certificat</strong>: {tlsInfo.days_remaining}</p>
                                )}
                                {tlsInfo.days_remaining !== undefined && tlsInfo.days_remaining < 30 && (
                                    <p>⚠ Il reste moins de 30 jours de validité pour ce certificat.</p>
                                )}
                            </div>
                        </Card.Body>
                    </Card>
                ) : (
                    <Card>
                        <Card.Body>
                            <Card.Title><h3>Informations du certificat TLS non disponibles <span><IconWithTooltip text="Le certificat TLS (Transport Layer Security) garantit la confidentialité et l'intégrité des données échangées entre votre navigateur et le serveur. Il contient des informations sur l'émetteur, la période de validité et d'autres détails essentiels. Vérifier ces données vous permet de vous assurer que la communication avec le serveur est sécurisée et qu'aucune tentative d'interception n'est en cours." /></span></h3></Card.Title>
                            <p>❌ Le certificat TLS est manquant sur ce domaine.</p>
                        </Card.Body>
                    </Card>
                )}

                {securityTxtResult && (
                    <Card>
                        <Card.Body>
                            <Card.Title><h3>Présence du fichier security.txt <span><IconWithTooltip text="Le fichier security.txt est un standard qui permet aux chercheurs en sécurité de savoir à qui rapporter des vulnérabilités sur un site web. S'il est présent, cela signifie que l'organisation est proactive en matière de sécurité et encourage les rapports de bugs. C'est un indicateur positif pour la sécurité de ce domaine." /></span></h3></Card.Title>
                            {securityTxtResult[0] === true ? (
                                <>
                                    <p>✅ Il y a un fichier Security.txt :</p>
                                    <pre>{JSON.stringify(securityTxtResult[1], null, 2)}</pre>
                                </>
                            ) : (
                                <p>❌ Il n'y a pas de fichier Security.txt.</p>
                            )}
                        </Card.Body>
                    </Card>
                )}

                {mailSecurityResult && (
                    <Card className="mail-security-card">
                        <Card.Body>
                            <Card.Title><h3>Politique de sécurité des e-mails <span><IconWithTooltip text="La politique de sécurité des emails, composée de DKIM, SPF, et DMARC, renforce l'authenticité et la fiabilité des messages électroniques en empêchant la falsification de l'expéditeur, en spécifiant les serveurs de messagerie autorisés et en définissant comment traiter les emails non authentifiés." /></span></h3></Card.Title>
                            <div>
                                {mailSecurityResult.DKIM ? (
                                    <div>
                                        <p>✅ DKIM activé :</p>
                                        <pre>{mailSecurityResult.DKIM_TXT[0]}</pre>
                                    </div>
                                ) : (
                                    <p>❌ DKIM désactivé</p>
                                )}

                                {mailSecurityResult.DMARC ? (
                                    <div>
                                        <p>✅ DMARC activé :</p>
                                        <pre>{mailSecurityResult.DMARC_TXT[0]}</pre>
                                    </div>
                                ) : (
                                    <p>❌ DMARC désactivé</p>
                                )}

                                {mailSecurityResult.SPF ? (
                                    <div>
                                        <p>✅ SPF activé :</p>
                                        <pre>{mailSecurityResult.SPF_TXT[0]}</pre>
                                    </div>
                                ) : (
                                    <p>❌ SPF désactivé</p>
                                )}
                            </div>
                        </Card.Body>
                    </Card>
                )}

                {whoisResult && (
                    <Card>
                        <Card.Body>
                            <Card.Title><h3>Whois <span><IconWithTooltip text="Les informations WHOIS fournissent des détails sur le propriétaire d'un nom de domaine, y compris son nom, son organisation, son pays, et ses coordonnées. Cela aide à identifier et à contacter les responsables d'un site web en cas de besoin." /></span></h3></Card.Title>
                            <p><strong>Ville</strong>: {whoisResult.City}</p>
                            <p><strong>Pays</strong>: {whoisResult.Country}</p>
                            <p><strong>Nom</strong>: {whoisResult.Name}</p>
                            <p><strong>Organisation</strong>: {whoisResult.Org}</p>
                            <p><strong>Téléphone</strong>: {whoisResult.Phone}</p>
                            <p><strong>Registrar</strong>: {whoisResult.Registrar}</p>
                            <p><strong>Expiration du domaine</strong>: {whoisResult.domain_expiration}</p>
                        </Card.Body>
                    </Card>
                )}

                {dnssecResult && (
                    <Card>
                        <Card.Body>
                            <Card.Title><h3>DNSSEC <span><IconWithTooltip text="DNSSEC (Domain Name System Security Extensions) est une technologie cruciale pour la sécurité en ligne. Elle protège contre la falsification des données DNS, assurant ainsi l'authenticité des informations de domaine. Sans DNSSEC, les attaques de type 'cache poisoning' et 'man-in-the-middle' peuvent compromettre la sécurité des utilisateurs en les redirigeant vers des sites malveillants. En utilisant DNSSEC, vous garantissez la confiance et l'intégrité des communications en ligne." /></span></h3></Card.Title>
                            {dnssecResult[0] === true ? (
                                <p>✅ DNSSEC activé :</p>
                            ) : (
                                <p>❌ DNSSEC désactivé</p>
                            )}
                            {dnssecResult[1] && dnssecResult[1].length > 0 && (
                                <ul>
                                    {dnssecResult[1].map((record, index) => (
                                        <li key={index}>{record}</li>
                                    ))}
                                </ul>
                            )}
                        </Card.Body>
                    </Card>
                )}

                {headersResult && (
                    <Card>
                        <Card.Body>
                            <Card.Title><h3>En-têtes de sécurité <span><IconWithTooltip text="Les en-têtes de sécurité HTTP sont des instructions fournies par un serveur web pour spécifier comment un navigateur doit interagir avec un site. Ils sont cruciaux pour protéger contre diverses menaces, comme les attaques par injection de scripts, les tentatives de détournement, et les vulnérabilités liées aux contenus." /></span></h3></Card.Title>
                            <div className="table-responsive">
                                <table className="table table-bordered table-hover">
                                    <thead>
                                    <tr>
                                        <th scope="col">En-tête</th>
                                        <th scope="col">Statut</th>
                                        <th scope="col">Valeur</th>
                                    </tr>
                                    </thead>
                                    <tbody>
                                    {Object.keys(headersResult).map(header => (
                                        <tr key={header} className={headersResult[header][0] ? 'table-success' : 'table-danger'}>
                                            <td>{header}</td>
                                            <td>{headersResult[header][0] ? '✅' : '❌'}</td>
                                            <td>{headersResult[header][1]}     <IconWithTooltip text={headersInfo[header]} /></td>
                                        </tr>
                                    ))}
                                    </tbody>
                                </table>
                            </div>
                        </Card.Body>
                    </Card>
                )}

                {analyserResult && (
                    <Card className="analyzer-card">
                        <Card.Body>
                            <Card.Title><h3>Analyse des ports et services ouverts <span><IconWithTooltip text="L'analyse des ports et services ouverts examine les points d'entrée accessibles d'un serveur. Elle identifie les services qui écoutent sur ces ports. Les vulnérabilités potentielles peuvent résulter de services obsolètes, mal configurés ou non mis à jour. Elles peuvent être exploitées par des attaquants pour compromettre la sécurité du système." /></span></h3></Card.Title>
                            {Object.entries(analyserResult).map(([ip, details]) => (
                                <div key={ip}>
                                    <Card.Title>IP: {ip}</Card.Title>
                                    <p>Domaine: {details.Domaine}</p>
                                    <div className="mt-3">
                                        {details["Ports ouverts"].map((portInfo, index) => (
                                            <Card key={index} className="mb-3">
                                                <Card.Body>
                                                    <Card.Title><strong>Port</strong>: {portInfo.Port} { [23, 88, 3389, 21, 22, 3306, 5432, 8080, 8443, 25, 587, 8090, 8000].includes(portInfo.Port) && (<span className="warning-icon"><WarningPortWithTooltip text={portsInfo[portInfo.Port]} /></span>) }</Card.Title>
                                                    <p>Service: {portInfo.Service}</p>
                                                    {portInfo["Vulnérabilités"].length > 0 && (
                                                        <div>
                                                            <p>Vulnérabilités :</p>
                                                            <ul>
                                                                {showMoreVulnerabilities
                                                                    ? portInfo["Vulnérabilités"].map((vuln, index) => (
                                                                        <li key={index}>
                                                                            <strong>CVE: </strong> {vuln.CVE}<br />
                                                                            <strong>Criticité: </strong>
                                                                            <span
                                                                                className={`criticite ${
                                                                                    vuln.Criticité.toLowerCase() === "faible"
                                                                                        ? "criticite-faible"
                                                                                        : vuln.Criticité.toLowerCase() === "moyenne"
                                                                                            ? "criticite-moyenne"
                                                                                            : vuln.Criticité.toLowerCase() === "élevée"
                                                                                                ? "criticite-haute"
                                                                                                : "criticite-critique"
                                                                                }`}
                                                                            >{vuln.Criticité}</span><br />
                                                                            <strong>Description:</strong> {vuln.Description}<br />
                                                                            <strong>Score CVSS:</strong> {vuln["Score CVSS"]}<br />
                                                                        </li>
                                                                    ))
                                                                    : portInfo["Vulnérabilités"].slice(0, 3).map((vuln, index) => (
                                                                        <li key={index}>
                                                                            <strong>CVE: </strong> {vuln.CVE}<br />
                                                                            <strong>Criticité: </strong>
                                                                            <span
                                                                                className={`criticite ${
                                                                                    vuln.Criticité.toLowerCase() === "faible"
                                                                                        ? "criticite-faible"
                                                                                        : vuln.Criticité.toLowerCase() === "moyenne"
                                                                                            ? "criticite-moyenne"
                                                                                            : vuln.Criticité.toLowerCase() === "élevée"
                                                                                                ? "criticite-haute"
                                                                                                : "criticite-critique"
                                                                                }`}
                                                                            >{vuln.Criticité}</span><br />
                                                                            <strong>Description:</strong> {vuln.Description}<br />
                                                                            <strong>Score CVSS:</strong> {vuln["Score CVSS"]}<br />
                                                                        </li>
                                                                    ))
                                                                }
                                                            </ul>
                                                            {portInfo["Vulnérabilités"].length > 3 && (
                                                                <button
                                                                    className="show-more-button"
                                                                    onClick={handleShowMoreVulnerabilities}
                                                                >
                                                                    {showMoreVulnerabilities ? 'Afficher moins' : 'Afficher toutes les vulnérabilités'}
                                                                </button>
                                                            )}
                                                        </div>
                                                    )}
                                                </Card.Body>
                                            </Card>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </Card.Body>
                    </Card>
                )}
            </div>
        </div>
    );
}

    export default Results;
