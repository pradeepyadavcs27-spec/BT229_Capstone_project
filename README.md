# BT229_Capstone_project
Major Project

## Dataset
Historical Cowrie honeypot logs: 68 files, April to June 2021, about 5.18 million events,
10,103 unique attacker IPs. Source: PASTE LINK HERE.
Place the logs in `datasets/cowrie_dataset/logs/`. The dataset is not committed to git.

## Machine learning
`train_model.py` builds one feature row per attacker IP, labels brute-force IPs with the
10-failures-in-60-seconds rule, and trains a Random Forest (supervised) and an Isolation Forest
(unsupervised).

    pip install -r requirements.txt
    python train_model.py datasets/cowrie_dataset/logs

Random Forest on a 25% held-out test set: precision 0.965, recall 0.991, F1 0.978.
Labels come from the rule-based detector, so this measures how well behavior reproduces that
rule, not independent ground truth. The Isolation Forest agreed poorly with the brute-force
label (precision 0.10).
