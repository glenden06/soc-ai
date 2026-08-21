# Politique de securite

## Versions supportees

| Version | Support |
|---|---|
| 1.0.x | Oui |
| < 1.0 | Non |

## Signaler une vulnerabilite

N'ouvrez pas d'issue publique pour une faille de securite. Utilisez l'onglet
Security de GitHub, fonction *Report a vulnerability*, ou ecrivez a l'adresse de
contact indiquee dans le profil de l'organisation.

Merci d'inclure une description du probleme, les etapes de reproduction, la
version concernee et l'impact estime. Vous recevrez un accuse de reception sous
72 heures et un point d'avancement sous 7 jours. Nous vous tiendrons informe
jusqu'au correctif et vous serez credite dans les notes de version, sauf si vous
preferez rester anonyme.

## Deployer SOC-AI de maniere sure

SOC-AI traite des journaux de securite : la compromission de l'instance donne
une vision complete des attaques subies et des comptes concernes.

- **N'exposez jamais l'API sur Internet sans protection.** La v1.0 n'a pas d'authentification. Placez-la derriere un VPN, un reverse proxy authentifie ou une restriction par IP.
- **Isolez le volume de donnees.** La base SQLite contient les journaux bruts. Chiffrez le disque hote et limitez l'acces au volume `socai-data`.
- **Ne codez aucun secret en dur.** La cle API passe par le fichier `.env`, ignore par git. Faites tourner la cle si elle a pu fuiter.
- **Restreignez le montage des journaux en lecture seule.** Le compose fournit deja `./logs:/logs:ro`.
- **Les conteneurs tournent avec un utilisateur non privilegie.** Ne les repassez pas en root pour contourner un probleme de droits : corrigez les droits du volume.
- **Surveillez la sortie reseau** si vous utilisez le triage cloud. Seul `api.anthropic.com` doit etre joignable depuis le conteneur `llm_agent`.

## Donnees personnelles et RGPD

Les journaux contiennent des donnees personnelles au sens du RGPD : adresses IP,
identifiants de comptes, parfois des adresses e-mail dans les URL.

- Avant tout envoi vers un LLM cloud, l'agent masque les adresses e-mail et tronque le journal brut a 1500 caracteres.
- `SOCAI_SEND_IP=false` masque egalement les adresses IP dans le contexte envoye au modele.
- Pour un traitement strictement interne, utilisez Ollama : aucune donnee ne quitte alors votre reseau.
- Definissez une duree de retention, 90 jours au maximum est un point de depart raisonnable, et purgez la table `events` en consequence.
- Documentez ce traitement dans votre registre et, si votre analyse le justifie, dans une AIPD.
- N'envoyez jamais de donnees de sante, de donnees bancaires ou de contenus de messages a un LLM cloud.

## Perimetre de la v1.0

Fonctions volontairement absentes, a prendre en compte dans votre analyse de
risque : authentification et gestion multi-utilisateurs, chiffrement de la base
au repos, journal d'audit des consultations, signature des exports.
