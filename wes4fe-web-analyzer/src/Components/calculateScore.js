const calculateScore = () => {
    let score = 302;

    // Certificat TLS 9 points
    if (document.body.innerHTML.includes('❌ Le certificat TLS est manquant sur ce domaine')) {
        score -= 9;
    }

    // DNSSEC 6 points
    if (document.body.innerHTML.includes('❌ DNSSEC désactivé')) {
        score -= 6;
    }

    // Mail security 28 points
    if (document.body.innerHTML.includes('❌ DKIM désactivé')) {
        score -= 10;
    }

    if (document.body.innerHTML.includes('❌ DMARC désactivé')) {
        score -= 9;
    }

    if (document.body.innerHTML.includes('❌ SPF désactivé')) {
        score -= 9;
    }

    // Headers HTTP Security 71 points
    const headers = document.querySelectorAll('.table tbody tr'); // Sélectionnez tous les éléments tr du tableau

    headers.forEach(row => {
        const header = row.children[0].textContent;
        const status = row.children[1].textContent;

        if (status === '❌') {
            switch (header) {
                case 'Content-Security-Policy':
                    score -= 9;
                    break;
                case 'Cookie':
                    score -= 4;
                    break;
                case 'Cross-origin Resource Sharing':
                    score -= 10;
                    break;
                case 'HTTP Redirections':
                    score -= 4;
                    break;
                case 'HTTP Strict Transport Security':
                    score -= 9;
                    break;
                case 'Referrer Policy':
                    score -= 5;
                    break;
                case 'Subresource Integrity':
                    score -= 8;
                    break;
                case 'X-Content-Type-Options':
                    score -= 9;
                    break;
                case 'X-Frame-Options':
                    score -= 6;
                    break;
                case 'X-XSS-Protection':
                    score -= 7;
                    break;
                default:
                    break;
            }
        }
    });

    // Ports 88 points
    if (document.body.innerHTML.includes('<strong>Port</strong>: 23 <span class="warning-icon">')) {
        score -= 11;
    }

    if (document.body.innerHTML.includes('<strong>Port</strong>: 88 <span class="warning-icon">')) {
        score -= 8;
    }

    if (document.body.innerHTML.includes('<strong>Port</strong>: 3389 <span class="warning-icon">')) {
        score -= 10;
    }

    if (document.body.innerHTML.includes('<strong>Port</strong>: 21 <span class="warning-icon">')) {
        score -= 11;
    }

    if (document.body.innerHTML.includes('<strong>Port</strong>: 22 <span class="warning-icon">')) {
        score -= 8;
    }

    if (document.body.innerHTML.includes('<strong>Port</strong>: 3306 <span class="warning-icon">')) {
        score -= 8
    }

    if (document.body.innerHTML.includes('<strong>Port</strong>: 5432 <span class="warning-icon">')) {
        score -= 8;
    }

    if (document.body.innerHTML.includes('<strong>Port</strong>: 8443 <span class="warning-icon">')) {
        score -= 8;
    }

    if (document.body.innerHTML.includes('<strong>Port</strong>: 25 <span class="warning-icon">')) {
        score -= 8;
    }

    if (document.body.innerHTML.includes('<strong>Port</strong>: 587 <span class="warning-icon">')) {
        score -= 8;
    }

    // Vulns shodan 100 points
    if (document.body.innerHTML.includes('<p class="note_shodan" style="display: none;">A</p>')) {
        score -= 25;
    } else if (document.body.innerHTML.includes('<p class="note_shodan" style="display: none;">B</p>')) {
        score -= 50;
    } else if (document.body.innerHTML.includes('<p class="note_shodan" style="display: none;">C</p>')) {
        score -= 75;
    } else if (document.body.innerHTML.includes('<p class="note_shodan" style="display: none;">D</p>')) {
        score -= 100;
    }

    return Math.max(score, 0);
};

export default calculateScore;