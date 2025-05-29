# Shariks Chain - Whitepaper (v1.1 – mai 2025)

## Introduction
Shariks Chain est une blockchain de nouvelle génération développée en Rust, pensée pour être légère, écologique et résolument communautaire. Elle repose sur un mécanisme hybride combinant le Proof of Stake (PoS) et le Proof of Relay (PoR)

## Vision
Créer un réseau 100 % souverain, économe en ressources, sans Proof of Work, et dont les récompenses sont redistribuées à la communauté selon la participation réelle - sans mint, ni burn

---

## Mécanismes clés

### Proof of Relay (PoR)
- Chaque wallet peut parrainer de nouveaux utilisateurs
- Le réseau récompense les parrainages : chaque transaction émise par un filleul génère des récompenses pour son parrain.
- Illimité dans le temps : tant que le filleul est actif, le parrain continue de recevoir des récompenses.
- **Bonus Parrainage** : les 100 premiers filleuls d’un utilisateur lui rapportent 10% de récompense en plus à vie.

### Proof of Stake (PoS) - Staking automatique
- Toute adresse détenant des jetons reçoit des "dividendes" mensuels issus des frais de transactions.
- Pas de génération magique de tokens : les récompenses proviennent exclusivement des **frais collectés**.
- Un système comptable tient compte du **temps exact de détention**, malgré les mouvements, pour assurer une distribution équitable (type "livret A").
- Plafond de prise en compte : maximum 1 000 000 SRKS par wallet dans le calcul des scores (pour éviter les dominations).

### Inactivité
- Si un wallet ne s’est **pas connecté au réseau depuis 1 an**, il **cesse temporairement de recevoir** des récompenses.
- La distribution reprend de zéro dès qu’il redevient actif.

---

## Économie et frais

### Offre totale
- 100 000 000 tokens SRKS (100 millions).

### Répartition initiale
- 80% pour la vente publique (ICO ou distribution équitable).
- 10% pour les récompenses de parrainage (en prévention de bug/faille).
- 10% pour la réserve/staking/dividendes (en prévention de bug/faille).

### Frais de transaction
- **1%** par transaction.
- **Plafond** : ne peut pas dépasser **100 SRKS** (pour une base de 1SRKS = 0.01$, ce plafond sera ensuite adapté en temps réel afin de ne pas dépasser les 1$ symbolique).

### Répartition des frais
| Catégorie            | Répartition normale | Si l’expéditeur fait partie des 100 premiers filleuls d’un parrain |
|----------------------|---------------------|------------------------------------------------------------|
| Parrainage           | 20%                 | 30%                                                       |
| Fondateur/infra      | 40%                 | 30%                                                       |
| Staking/Dividendes   | 10%                 | 10%                                                       |
| Trésorerie           | 30%                 | 30%                                                       |

---

### Ledger & synchronisation
- Le solde de chaque wallet est recalculé en temps réel via une base de données PostgreSQL.
- Chaque jour :
- - Un snapshot journalier est pris.
- - Une vérification de cohérence complète est effectuée (hashs, soldes, supply).
- Le système est conçu pour minimiser la RAM utilisée (SQL streamé, pas de HashMap Rust).

---

### Mécanisme à l’étude : expiration des wallets inactifs
**Ce mécanisme n’est pas actif pour le moment**

Un système de réaffectation des fonds inactifs au-delà de 20 ans est actuellement à l’étude. L’objectif est de réinjecter dans l’économie les tokens perdus ou abandonnés, tout en garantissant :

- Transparence complète,
- Notifications préalables,
- Et, si possible, une méthode de récupération post-expiration (preuve d'identité, héritage, etc.).

---

## Autres principes
- **Pas de token burn** : aucun token n’est détruit.
- **Pas de mint infini** : l’offre est **limitée** à la genèse, aucun jeton supplémentaire ne sera généré.

---

## Objectifs futurs
- Ajout d’un explorateur de transactions.
- Frontend simple pour visualiser les soldes, historiques, et système de parrainage.
- API publique pour intégration tierce.
- Mode serveur + client avec architecture actix-web + PostgreSQL.
- Sécurisation via HashiCorp Vault ou systèmes externes pour les clés sensibles.

---

## Adresse de genèse
L'adresse `SRKS_genesis` détient la totalité des 100 millions de tokens au démarrage.
Elle sert à distribuer les jetons selon la logique ci-dessus.
