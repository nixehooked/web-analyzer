# WeS4FE Web Analyzer

Web Analyzer est une application web qui permet d'analyser un nom de domaine donné pour obtenir diverses informations sur celui-ci, notamment les informations Whois, les ports ouverts, la sécurité des e-mails, la présence de security.txt, HSTS, DNSSEC, les vulnérabilités potentielles associées aux versions des services associés aux ports.


## Installation Docker

Pour exécuter cette application localement via Docker, suivez ces étapes :

1. Clonez ce dépôt :

   ```bash
   git clone https://github.com/votre-utilisateur/web-analyzer.git

2. Naviguez dans le dossier du projet :

   ```bash
   cd web-analyzer

3. Executer le container :

   ```bash
   docker compose up

4. Ouvrir l'application :

   ```bash
   http://localhost:3000

## Utilisation

  Sur la page d'accueil, saisissez le nom de domaine que vous souhaitez analyser dans le champ d'entrée.

  Cliquez sur le bouton "Analyser!".

  L'application récupérera et affichera les informations demandées pour le domaine donné.

## Fonctionnalités

  Informations Whois: Obtenez des informations sur le domaine telles que le registrar, l'organisation, le pays, la ville, le nom du titulaire, le numéro de téléphone et la date d'expiration.

  Ports ouverts: Découvrez la liste des ports ouverts sur le domaine, ainsi que les vulnérabilités potentielles associées à ces ports.

  Sécurité des e-mails: Vérifiez la configuration de sécurité des e-mails, notamment DKIM, SPF, DMARC.

  Présence de security.txt: Découvrez si le domaine a un fichier de politique de sécurité (security.txt).

  HSTS: Vérifiez si HSTS (HTTP Strict Transport Security) est activé sur le domaine.

  DNSSEC: Vérifiez la présence de DNSSEC (Domain Name System Security Extensions).

  Vulnérabilités potentielles: Identifiez les vulnérabilités potentielles associées aux versions des services associés aux ports ouverts.

## Contribuer

Si vous souhaitez contribuer à ce projet, n'hésitez pas à ouvrir une pull request avec vos modifications.
