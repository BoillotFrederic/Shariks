# Shariks Chain – Whitepaper (English)

## Introduction
Shariks Chain is a next-generation blockchain developed in Rust, designed to be lightweight, eco-friendly, and community-driven. It relies on a hybrid mechanism combining Proof of Stake (PoS) and Proof of Relay (PoR).

## Vision
To build a fully sovereign network, resource-efficient, without Proof of Work, where rewards are redistributed to the community based on actual participation — with no minting or burning of tokens.

---

## Core Mechanisms

### Proof of Relay (PoR)
- Each wallet can sponsor new users.
- The network rewards sponsorship: each transaction from a sponsored user generates rewards for their sponsor.
- Timeless: as long as the sponsored user remains active, their sponsor continues to receive rewards.
- **Sponsorship Bonus**: the first 100 sponsored users of any wallet generate +10% lifetime rewards for their sponsor.

### Proof of Stake (PoS) – Automatic Staking
- Any address holding tokens receives monthly "dividends" derived from transaction fees.
- No magical token generation: rewards come **exclusively from collected fees**.
- A ledger system accounts for the **exact holding time**, even with token movement, ensuring fair distribution (like a savings account).
- Max stake cap: a maximum of 1,000,000 SRKS is considered per wallet when computing staking scores (to prevent domination).

### Inactivity
- If a wallet has **not connected to the network for over 1 year**, it **temporarily stops receiving** staking rewards.
- Rewards resume from zero once the wallet becomes active again.

---

## Tokenomics & Fees

### Total Supply
- 100,000,000 SRKS tokens (100 million).

### Initial Distribution
- 80% for public sale (ICO or fair distribution).
- 10% for sponsorship rewards (as a safeguard against bugs/exploits).
- 10% for reserve/staking/dividends (as a safeguard against bugs/exploits).

### Transaction Fees
- **1%** per transaction.
- **Cap**: cannot exceed **100 SRKS**  
  (based on a projected value of 1 SRKS = $0.01, this cap will adjust dynamically to stay under $1).

### Fee Distribution

| Category           | Standard Distribution | If sender is among a sponsor’s first 100 referees |
|--------------------|------------------------|--------------------------------------------------|
| Sponsorship        | 20%                    | 30%                                             |
| Founder/Infra      | 40%                    | 30%                                             |
| Staking/Dividends  | 10%                    | 10%                                             |
| Treasury           | 30%                    | 30%                                             |

---

## Ledger & Synchronization
- Each wallet’s balance is recalculated in real time via a PostgreSQL database.
- Every day:
  - A daily snapshot is taken.
  - A full consistency check is performed (hashes, balances, supply).
- The system is designed to minimize RAM usage (streamed SQL, no Rust HashMaps).

---

## Experimental Mechanism: Expiration of Inactive Wallets  
**This mechanism is currently under review and not active**

A system to reassign inactive funds after 20 years is being considered. The goal is to re-inject lost or abandoned tokens back into the economy while ensuring:

- Full transparency,
- Advance notifications,
- And if possible, post-expiration recovery options (ID proof, inheritance, etc.).

---

## Other Principles
- **No token burn**: no tokens are ever destroyed.
- **No infinite minting**: supply is **fixed** at genesis — no additional tokens will ever be created.

---

## Future Objectives
- Add a transaction explorer.
- Simple frontend to display balances, history, and sponsorship relationships.
- Public API for third-party integrations.
- Server + client architecture with actix-web + PostgreSQL.
- Securing sensitive keys via HashiCorp Vault or external systems.

---

## Genesis Address
The address `SRKS_genesis` holds all 100 million tokens at launch.  
It is used to distribute tokens according to the logic described above.

---
---
---

# Shariks Chain - Whitepaper (Français)

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
