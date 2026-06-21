import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

print("Генерация датасета:")
N = 21000

legit_tcp = pd.DataFrame({
    'length': np.random.randint(54, 1500, size=int(N * 0.3)),
    'protocol_num': 6,
    'label': 'Норма'
})

legit_udp = pd.DataFrame({
    'length': np.random.randint(60, 1100, size=int(N * 0.3)),
    'protocol_num': 17,
    'label': 'Норма'
})

attack_icmp_flood = pd.DataFrame({
    'length': np.random.randint(1500, 2500, size=int(N * 0.08)),
    'protocol_num': 1,
    'label': 'Атака: ICMP Flood'
})

attack_icmp_scan = pd.DataFrame({
    'length': np.random.randint(50, 100, size=int(N * 0.08)),
    'protocol_num': 1,
    'label': 'Атака: ICMP Ping Sweep'
})

attack_udp_flood = pd.DataFrame({
    'length': np.random.randint(40, 50, size=int(N * 0.08)),
    'protocol_num': 17,
    'label': 'Атака: UDP Flood'
})

attack_udp_amp = pd.DataFrame({
    'length': np.random.randint(1350, 1500, size=int(N * 0.08)),
    'protocol_num': 17,
    'label': 'Атака: UDP Amplification'
})

attack_tcp_syn = pd.DataFrame({
    'length': np.random.randint(40, 45, size=int(N * 0.08)),
    'protocol_num': 6,
    'label': 'Атака: SYN Flood'
})

df = pd.concat([
    legit_tcp, legit_udp,
    attack_icmp_flood, attack_icmp_scan,
    attack_udp_flood, attack_udp_amp,
    attack_tcp_syn
]).sample(frac=1).reset_index(drop=True)

print("Обучение модели...")
X = df[['length', 'protocol_num']]
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nОбщая точность модели: {accuracy * 100:.2f}%\n")

print("Отчет классификации:")
print(classification_report(y_test, y_pred))

joblib.dump(model, 'traffic_ml_model.pkl')
print("Модель сохранена.")