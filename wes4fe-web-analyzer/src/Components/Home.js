import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import logo from '../WS_LOGO_BLANC.svg';
import '../Styles/Home.css';

const Home = () => {
    const [domain, setDomain] = useState('');
    const navigate = useNavigate();

    useEffect(() => {
        const canvas = document.getElementById('matrix-canvas');
        const context = canvas.getContext('2d');

        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const charactersArray = characters.split('');

        const fontSize = 14;
        const columns = canvas.width / fontSize;

        const drops = [];

        for (let i = 0; i < columns; i++) {
            drops[i] = 1;
        }

        const draw = () => {
            context.fillStyle = 'rgba(0, 0, 0, 0.05)';
            context.fillRect(0, 0, canvas.width, canvas.height);

            context.fillStyle = '#6800ED';
            context.font = `${fontSize}px monospace`;

            for (let i = 0; i < drops.length; i++) {
                const randomCharacter = charactersArray[Math.floor(Math.random() * charactersArray.length)];
                context.fillText(randomCharacter, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }

                drops[i]++;
            }
        };

        const animate = () => {
            draw();
            requestAnimationFrame(animate);
        };

        animate();
    }, []);

    const handleDomainChange = (event) => {
        setDomain(event.target.value);
    };

    const handleSearch = async () => {
        try {
            navigate(`/results?cible=${encodeURIComponent(domain)}`);
        } catch (error) {
            console.error('Erreur lors de la navigation vers les résultats:', error);
        }
    };

    return (
        <div>
            <canvas id="matrix-canvas"></canvas>
            <div className="content">
                <div className="logo-container">
                    <img src={logo} alt="Logo" className="logo" />
                    <h1 className="title">Web Analyser</h1>
                </div>
                <div className="input-container">
                    <input
                        type="text"
                        value={domain}
                        onChange={handleDomainChange}
                        className="input"
                        placeholder="Entrez un nom de domaine..."
                    />
                    <button onClick={handleSearch} className="button" type={"submit"}>
                        Analyser!
                    </button>
                </div>
                <div className="security-info">
                    <div className="security-explanation">
                        <h2>Ce scan recouvre :</h2>
                        <p>✅Informations Whois sur le domaine</p>
                        <p>✅La liste des ports ouverts</p>
                        <p>✅La configuration de sécurité mail (DKIM, DMARC, SPF)</p>
                        <p>✅Présence d'un security.txt</p>
                        <p>✅HSTS activé ou non</p>
                        <p>✅Présence DNSSEC</p>
                        <p>✅Vulnérabilités potentielles associées aux versions des services associés aux ports</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Home;
