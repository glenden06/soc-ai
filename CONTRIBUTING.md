# Contribuer a SOC-AI

Merci de votre interet. Les contributions les plus utiles au projet sont les
nouvelles regles Sigma, les parsers de formats supplementaires et les
corrections de faux positifs constates en production.

## Preparer son environnement

```bash
git clone https://github.com/OWNER/soc-ai.git && cd soc-ai
python -m venv .venv && source .venv/bin/activate
pip install -r parser/requirements.txt -r engine/requirements.txt \
            -r llm_agent/requirements.txt -r api/requirements.txt
pip install pytest httpx ruff
python -m pytest tests/ -v
```

## Flux de travail

1. Ouvrez une issue avant de commencer un developpement important, afin d'eviter les doublons.
2. Partez de `dev`, jamais de `main`.
3. Nommez votre branche `feat/<sujet>`, `fix/<sujet>` ou `rule/<identifiant>`.
4. Ecrivez un test pour tout comportement nouveau ou corrige.
5. Verifiez que `ruff check .` et `python -m pytest tests/` passent en local.
6. Ouvrez une pull request vers `dev` en decrivant le probleme resolu et la maniere de le reproduire.

## Conventions de commit

Le projet suit Conventional Commits.

```
feat(engine): ajout du modificateur endswith
fix(parser): gestion des lignes auth.log tronquees
rule(win): detection de la creation de tache planifiee
docs(readme): correction du lien vers l architecture
```

## Ajouter une regle Sigma

Deposez un fichier YAML dans `engine/rules/` en suivant ce gabarit :

```yaml
title: Nom lisible de la regle
id: PREFIXE-00X
status: experimental
description: Ce que la regle detecte, en une phrase.
author: votre pseudo
logsource:
  product: linux
  service: sshd
detection:
  selection:
    source_type: ssh
    action: auth_failure
  timeframe: 60s
  condition: selection | count() by source_ip > 5
falsepositives:
  - Cas legitime connu
level: high
tags:
  - attack.credential_access
  - attack.t1110.001
```

Regles a respecter :

- L'identifiant suit le format `PREFIXE-NNN` et reste unique dans le depot.
- Le champ `level` vaut `critical`, `high`, `medium`, `low` ou `informational`.
- Renseignez au moins un faux positif plausible : une regle sans faux positif documente est presque toujours trop large.
- Ajoutez un test dans `tests/test_engine.py` qui declenche la regle et un cas voisin qui ne la declenche pas.
- Ajoutez si possible quelques lignes representatives dans `samples/`.

Champs disponibles dans une selection : `timestamp`, `source_ip`, `user`,
`action`, `source_type`, plus toute cle presente dans le champ `extra` du
parser concerne, par exemple `event_id`, `object_name`, `user_agent`,
`path_decoded`, `status`.

## Ajouter un parser

Creez `parser/formats/<format>.py` exposant `SOURCE_TYPE` et une fonction
`parse(line)` qui renvoie un dictionnaire normalise ou `None`. Declarez le
module dans `parser/formats/__init__.py`, etendez `detect_format`, et couvrez
le nouveau format par des tests, y compris une ligne volontairement malformee.

Un parser ne doit jamais lever d'exception sur une ligne inattendue : il renvoie
`None` et laisse l'ingestion continuer.

## Style de code

- Python formate selon PEP 8, verifie par `ruff check .`, lignes de 110 caracteres maximum.
- Docstring sur toute fonction publique.
- Aucun secret dans le code : tout passe par des variables d'environnement.
- Les appels reseau et les acces base sont encadres par une gestion d'erreur explicite.
- Le JavaScript suit les conventions du projet Vite : composants fonctionnels, hooks, pas de dependance ajoutee sans discussion prealable.

## Signaler une vulnerabilite

N'ouvrez pas d'issue publique. Suivez la procedure decrite dans
[SECURITY.md](SECURITY.md).
