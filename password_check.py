import hashlib
import math
import re
import requests
import getpass # Pour une saisie sécurisée du mot de passe

# --- Logique d'analyse (Identique à app.py) ---

# Vitesses de craquage (H/s)
CRACKING_SPEEDS = {
    'md5': 1.2e12,
    'ntlm': 2.4e12,
    'sha256': 1.5e11,
    'bcrypt': 1.3e7,
    'scrypt': 5e5,
    'argon2': 2e5
}

# Patterns Regex communs
COMMON_PATTERNS = [
    re.compile(r'^password', re.IGNORECASE),
    re.compile(r'^admin', re.IGNORECASE),
    re.compile(r'^welcome', re.IGNORECASE),
    re.compile(r'^login', re.IGNORECASE),
    re.compile(r'^letmein', re.IGNORECASE),
    re.compile(r'^qwerty', re.IGNORECASE),
    re.compile(r'^abc123', re.IGNORECASE),
    re.compile(r'^123456'),
    re.compile(r'^iloveyou', re.IGNORECASE),
    re.compile(r'^monkey', re.IGNORECASE),
    re.compile(r'^dragon', re.IGNORECASE),
    re.compile(r'^master', re.IGNORECASE),
    re.compile(r'^sunshine', re.IGNORECASE),
    re.compile(r'^princess', re.IGNORECASE),
    re.compile(r'^football', re.IGNORECASE),
    re.compile(r'^\d+$'),  # Seulement des chiffres
    re.compile(r'^[a-z]+\d+$', re.IGNORECASE),  # Mot + chiffres
    re.compile(r'^[A-Z][a-z]+\d+$'),  # Maj + min + chiffres
    re.compile(r'^[A-Z][a-z]+\d+[!@#$%]$'),  # Pattern commun
]

def has_common_substitutions(pwd):
    """Vérifie les substitutions 'leet speak' courantes."""
    common_words_with_subs = [
        re.compile(r'p[@4]ssw[o0]rd', re.IGNORECASE),
        re.compile(r'[l1][o0]v[e3]', re.IGNORECASE),
        re.compile(r'[l1][e3]tm[e3][l1]n', re.IGNORECASE),
        re.compile(r'w[e3][l1]c[o0]m[e3]', re.IGNORECASE),
        re.compile(r'[a@]dm[l1]n', re.IGNORECASE),
        re.compile(r'm[o0]nk[e3]y', re.IGNORECASE),
        re.compile(r'dr[a@]g[o0]n', re.IGNORECASE)
    ]
    
    for pattern in common_words_with_subs:
        if pattern.search(pwd):
            return True
            
    sub_count = 0
    if re.search(r'@', pwd) and re.search(r'a', pwd, re.IGNORECASE): sub_count += 1
    if re.search(r'3', pwd) and re.search(r'e', pwd, re.IGNORECASE): sub_count += 1
    if re.search(r'\$', pwd) and re.search(r's', pwd, re.IGNORECASE): sub_count += 1
    if re.search(r'1', pwd) and re.search(r'[il]', pwd, re.IGNORECASE): sub_count += 1
    if re.search(r'7', pwd) and re.search(r't', pwd, re.IGNORECASE): sub_count += 1
    
    has_0_in_middle = re.search(r'[a-z]0[a-z]', pwd, re.IGNORECASE)
    if has_0_in_middle and re.search(r'o', pwd, re.IGNORECASE): sub_count += 1
    
    return sub_count >= 2

def check_hibp(password):
    """
    Vérifie le mot de passe contre l'API HIBP Pwned Passwords (k-Anonymity).
    Retourne True s'il est compromis, False sinon.
    """
    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            print(f"[Erreur HIBP: {response.status_code}]")
            return False
            
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return True
                
    except requests.RequestException as e:
        print(f"[Erreur de connexion à l'API HIBP: {e}]")
        return False
        
    return False

def calculate_realistic_crack_time(password, in_hibp):
    """Calcule le temps de craquage estimé en secondes."""
    if in_hibp:
        return {'seconds': 0, 'method': 'Trouvé dans base de données (HIBP)', 'hashType': 'dictionary'}

    length = len(password)
    
    if length < 6:
        return {'seconds': 0.01, 'method': 'Force brute (trop court)', 'hashType': 'NTLM'}

    for pattern in COMMON_PATTERNS:
        if pattern.search(password):
            rule_based_time = (10 ** (length - 4)) / 1e6
            return {
                'seconds': rule_based_time,
                'method': 'Attaque par règles (pattern détecté)',
                'hashType': 'BCRYPT'
            }

    if has_common_substitutions(password):
        leet_time = (10 ** (length - 3)) / 1e5
        return {
            'seconds': leet_time,
            'method': 'Attaque leet speak (substitutions communes)',
            'hashType': 'BCRYPT'
        }

    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    
    if charset == 0: return {'seconds': 0.01, 'method': 'Inconnu', 'hashType': 'NTLM'}

    entropy = length * math.log2(charset)
    effective_len = min(length, 60)
    
    # Python gère les très grands entiers nativement
    combinations = charset ** effective_len

    hash_type, speed = ('NTLM', CRACKING_SPEEDS['ntlm'])
    if length >= 16 and charset >= 70:
        hash_type, speed = ('BCRYPT', CRACKING_SPEEDS['bcrypt'])
    elif length >= 12 and charset >= 52:
        hash_type, speed = ('SHA256', CRACKING_SPEEDS['sha256'])

    seconds_to_crack = (combinations / 2) / speed

    return {
        'seconds': seconds_to_crack,
        'method': 'Force brute pure (mot de passe aléatoire)',
        'hashType': hash_type,
        'entropy': round(entropy)
    }

def format_time_cli(seconds):
    """Formate les secondes pour un affichage console."""
    if seconds == 0: return 'INSTANTANÉ ⚡💀'
    if seconds < 1: return 'Moins d\'une seconde ⚡'
    if seconds < 60: return f"{math.ceil(seconds)} secondes"
    if seconds < 3600: return f"{math.ceil(seconds / 60)} minutes"
    if seconds < 86400: return f"{math.ceil(seconds / 3600)} heures"
    if seconds < 31536000: return f"{math.ceil(seconds / 86400)} jours"
    years = seconds / 31536000
    if years < 1000: return f"{math.ceil(years)} ans"
    if years < 1e6: return f"{years / 1000:.1f}K ans"
    if years < 1e9: return f"{years / 1e6:.1f}M ans"
    return f"{years / 1e9:.1f} Mds d'années 🛡️"

def main():
    """Fonction principale pour l'outil CLI."""
    try:
        password = getpass.getpass("Entrez votre mot de passe (ne sera pas affiché) : ")
        if not password:
            print("Aucun mot de passe entré.")
            return

        print("\nAnalyse en cours (vérification HIBP)...")
        
        is_pwned = check_hibp(password)
        crack_result = calculate_realistic_crack_time(password, is_pwned)
        
        checks = {
            'length': len(password) >= 12,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'numbers': bool(re.search(r'[0-9]', password)),
            'special': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'notCommon': not is_pwned
        }
        
        score = 0
        if checks['length']: score += 25
        if checks['uppercase']: score += 15
        if checks['lowercase']: score += 15
        if checks['numbers']: score += 15
        if checks['special']: score += 20
        if checks['notCommon']: score += 10
        if not checks['notCommon']: score = min(score, 15)

        strength = 'Très faible'
        if score >= 80: strength = 'Excellent'
        elif score >= 60: strength = 'Bon'
        elif score >= 40: strength = 'Moyen'
        elif score >= 20: strength = 'Faible'

        print("\n--- RÉSULTATS DE L'ANALYSE ---")
        
        # Barre de force
        bar_char = '█'
        bar_length = 20
        filled_length = int(score / 100 * bar_length)
        bar = bar_char * filled_length + '-' * (bar_length - filled_length)
        print(f"Force : {strength} [{bar}] ({score}/100)")

        # Temps de craquage
        time_str = format_time_cli(crack_result['seconds'])
        print(f"\nTemps de craquage estimé : {time_str}")
        print(f"  (Méthode: {crack_result['method']} | Hash: {crack_result['hashType']})")
        if 'entropy' in crack_result:
            print(f"  (Entropie: {crack_result.get('entropy')} bits)")
            
        # Critères
        print("\nCritères de sécurité :")
        print(f"  [{'✓' if checks['length'] else '✗'}] 12 caractères minimum")
        print(f"  [{'✓' if checks['uppercase'] else '✗'}] Lettres majuscules (A-Z)")
        print(f"  [{'✓' if checks['lowercase'] else '✗'}] Lettres minuscules (a-z)")
        print(f"  [{'✓' if checks['numbers'] else '✗'}] Chiffres (0-9)")
        print(f"  [{'✓' if checks['special'] else '✗'}] Caractères spéciaux (!@#...)")
        
        if checks['notCommon']:
            print("  [✓] Non trouvé dans les fuites de données (HIBP)")
        else:
            print("  [✗] ⚠️ TROUVÉ DANS LES FUITES DE DONNÉES (HIBP) - COMPROMIS!")
            
        # Suggestions
        print("\nConseils d'amélioration :")
        if not checks['notCommon']:
            print("  - 🚨 CRITIQUE : Changez ce mot de passe IMMÉDIATEMENT!")
        if re.search(r'^[a-z]+\d+$', password, re.IGNORECASE):
            print("  - ⚠️ Pattern prévisible détecté (mot + chiffres).")
        if has_common_substitutions(password):
            print("  - ⚠️ Substitutions communes détectées ('@' pour 'a', etc.).")
            
        if not checks['length']: print("  - Utilise au moins 12 caractères (16+ recommandé)")
        if not checks['uppercase']: print("  - Ajoute des lettres majuscules (A-Z)")
        if not checks['lowercase']: print("  - Ajoute des lettres minuscules (a-z)")
        if not checks['numbers']: print("  - Ajoute des chiffres (0-9)")
        if not checks['special']: print("  - Ajoute des caractères spéciaux (!@#...)")
        
        if checks['notCommon'] and score >= 80:
             print("  - ✅ Excellent! Continuez comme ça.")

    except KeyboardInterrupt:
        print("\nAnalyse annulée.")

if __name__ == '__main__':
    main()