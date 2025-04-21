# Shariks Chain — Whitepaper (en developpement)

## Introduction
Shariks est un réseau blockchain de nouvelle génération conçu pour être léger, économe en ressources, et centré sur l’engagement communautaire grâce à un mécanisme hybride alliant PoR (Proof of Relay) et PoS (Proof of Stake).

## Vision
Créer une crypto qui ne dépend pas de la puissance de calcul ou d'infrastructures complexes, tout en récompensant équitablement les utilisateurs actifs et engagés.

---

## Mécanismes clés

### Proof of Relay (PoR)
- Le réseau récompense les parrainages : chaque transaction émise par un filleul génère des récompenses pour son parrain.
- Illimité dans le temps : tant que le filleul est actif, le parrain continue de recevoir des récompenses.
- **Bonus Parrainage** : les 100 premiers filleuls d’un utilisateur lui rapportent 10% de récompense en plus à vie.

### Proof of Stake (PoS) — Staking automatique
- Toute adresse détenant des jetons reçoit des "dividendes" mensuels issus des frais de transactions.
- Pas de génération magique de tokens : les récompenses proviennent d’une **réserve de 10%** et des **frais collectés**.
- Un système comptable tient compte du **temps exact de détention**, malgré les mouvements, pour assurer une distribution équitable (type "livret A").

### Inactivité
- Si un wallet ne s’est **pas connecté au réseau depuis 1 an**, il **cesse temporairement de recevoir** des récompenses.
- La distribution reprend dès qu’il redevient actif.

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
- **Plafond** : ne peut pas dépasser **1 SRKS**.

### Répartition des frais
| Catégorie            | Répartition normale | Si l’expéditeur fait partie des 100 premiers filleuls d’un parrain |
|----------------------|---------------------|------------------------------------------------------------|
| Parrainage           | 20%                 | 30%                                                       |
| Fondateur/infra      | 40%                 | 30%                                                       |
| Staking/Dividendes   | 10%                 | 10%                                                       |
| Trésorerie           | 30%                 | 30%                                                       |


---

## Autres principes
- **Pas de token burn** : aucun token n’est détruit.
- **Pas de mint infini** : l’offre est **limitée** à la genèse, aucun jeton supplémentaire ne sera généré.

---

## Objectifs futurs
- Ajout d’un explorateur de transactions.
- Frontend simple pour visualiser les soldes, historiques, et système de parrainage.
- API publique pour intégration tierce.

---

## Adresse de genèse
L'adresse `SRKS_genesis` détient la totalité des 100 millions de tokens au démarrage.
Elle sert à distribuer progressivement les jetons selon la logique ci-dessus.
