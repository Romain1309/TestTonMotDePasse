import hashlib
import math
import re
import requests
from flask import Flask, jsonify, request, render_template_string

app = Flask(__name__)

CRACKING_SPEEDS = {
    'md5': 1.2e12,
    'ntlm': 2.4e12,
    'sha256': 1.5e11,
    'bcrypt': 1.3e7,
    'scrypt': 5e5,
    'argon2': 2e5
}

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
    re.compile(r'^\d+$'),  
    re.compile(r'^[a-z]+\d+$', re.IGNORECASE),  
    re.compile(r'^[A-Z][a-z]+\d+$'),  
    re.compile(r'^[A-Z][a-z]+\d+[!@#$%]$'),  
]

def has_common_substitutions(pwd):
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
    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            print(f"Erreur HIBP: {response.status_code}")
            return False 
            
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return True 
                
    except requests.RequestException as e:
        print(f"Erreur de connexion à l'API HIBP: {e}")
        return False 
        
    return False 

def calculate_realistic_crack_time(password, in_hibp):
    #si dans HIBP
    if in_hibp:
        return {'seconds': 0, 'method': 'Trouvé dans base de données (HIBP)', 'hashType': 'dictionary'}

    length = len(password)
    
    #mot de passe trop court
    if length < 6:
        return {'seconds': 0.01, 'method': 'Force brute (trop court)', 'hashType': 'NTLM'}

    # detection de patterns
    for pattern in COMMON_PATTERNS:
        if pattern.search(password):
            rule_based_time = (10 ** (length - 4)) / 1e6
            return {
                'seconds': rule_based_time,
                'method': 'Attaque par règles (pattern détecté)',
                'hashType': 'BCRYPT'
            }

    # detection de substitution
    if has_common_substitutions(password):
        leet_time = (10 ** (length - 3)) / 1e5
        return {
            'seconds': leet_time,
            'method': 'Attaque leet speak (substitutions communes)',
            'hashType': 'BCRYPT'
        }

    #calcul entropie (bruteforce)
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    
    if charset == 0: return {'seconds': 0.01, 'method': 'Inconnu', 'hashType': 'NTLM'}

    entropy = length * math.log2(charset)
    
    effective_len = min(length, 60)
    
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


@app.route('/analyze', methods=['POST'])
def analyze_password():
    data = request.json
    password = data.get('password')

    if not password:
        return jsonify({'error': 'Aucun mot de passe fourni'}), 400

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
    
    if not checks['notCommon']:
        score = min(score, 15)

    strength, color = 'Très faible', 'red'
    if score >= 80: strength, color = 'Excellent', 'green'
    elif score >= 60: strength, color = 'Bon', 'blue'
    elif score >= 40: strength, color = 'Moyen', 'yellow'
    elif score >= 20: strength, color = 'Faible', 'orange'

    suggestions = []
    if not checks['notCommon']:
        suggestions.append('🚨 CRITIQUE : Ce mot de passe est dans les bases de données compromises! Change-le IMMÉDIATEMENT!')
    
    if re.search(r'^[a-z]+\d+$', password, re.IGNORECASE):
        suggestions.append('⚠️ Pattern prévisible détecté : mot + chiffres à la fin. Mélange les caractères!')
    if has_common_substitutions(password):
        suggestions.append('⚠️ Substitutions communes détectées (@ pour a, 0 pour o). Les hackers connaissent ces astuces!')
    
    if not checks['length']: suggestions.append('Utilise au moins 12 caractères (16+ recommandé)')
    if not checks['uppercase']: suggestions.append('Ajoute des lettres majuscules (A-Z)')
    if not checks['lowercase']: suggestions.append('Ajoute des lettres minuscules (a-z)')
    if not checks['numbers']: suggestions.append('Ajoute des chiffres (0-9)')
    if not checks['special']: suggestions.append('Ajoute des caractères spéciaux (!@#$%^&*)')
    
    if not suggestions or (len(suggestions) <= 2 and checks['notCommon'] and len(password) < 16):
        suggestions.append('✅ Excellent! Pour encore plus de sécurité, vise 16+ caractères')

    return jsonify({
        'checks': checks,
        'score': score,
        'strength': strength,
        'color': color,
        'secondsToCrack': crack_result['seconds'],
        'crackMethod': crack_result['method'],
        'hashType': crack_result['hashType'],
        'entropy': crack_result.get('entropy'),
        'suggestions': suggestions
    })

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSIUL - Teste ton mot de passe</title>
    <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; }
        
        .spinner {
            border: 4px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top: 4px solid #EF4444; /* Rouge */
            width: 24px;
            height: 24px;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body class="bg-black">
    <div id="root"></div>

    {% raw %}
    <script type="text/babel">
        const { useState, useEffect, useCallback } = React;

        const Shield = ({ className }) => (
            <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
        );
        const AlertTriangle = ({ className }) => (
            <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
        );
        const CheckCircle = ({ className }) => (
            <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
        );
        const XCircle = ({ className }) => (
            <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
        );
        const Clock = ({ className }) => (
            <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
        );
        const Skull = ({ className }) => (
            <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z" />
            </svg>
        );
        const Eye = ({ className }) => (
            <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
            </svg>
        );
        const EyeOff = ({ className }) => (
            <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
            </svg>
        );
        
        const formatTime = (seconds) => {
            if (seconds === 0) return 'INSTANTANÉ ⚡💀';
            if (seconds < 1) return "Moins d'une seconde ⚡"; // CORRIGÉ
            if (seconds < 60) return `${Math.ceil(seconds)} secondes`;
            if (seconds < 3600) return `${Math.ceil(seconds / 60)} minutes`;
            if (seconds < 86400) return `${Math.ceil(seconds / 3600)} heures`;
            if (seconds < 31536000) return `${Math.ceil(seconds / 86400)} jours`;
            const years = seconds / 31536000;
            if (years < 1000) return `${Math.ceil(years)} ans`;
            if (years < 1e6) return `${(years / 1000).toFixed(1)}K ans`;
            if (years < 1e9) return `${(years / 1e6).toFixed(1)}M ans`;
            if (seconds === Infinity) return "Pratiquement jamais 🛡️";
            return `${(years / 1e9).toFixed(1)} Mds d'années 🛡️`;
        };

        function PasswordTester() {
            const [password, setPassword] = useState('');
            const [showPassword, setShowPassword] = useState(false);
            const [analysis, setAnalysis] = useState(null); // Contient les résultats OU un état de chargement
            const [isLoading, setIsLoading] = useState(false);

            useEffect(() => {
                if (!password) {
                    setAnalysis(null);
                    return;
                }

                setIsLoading(true);

                const analyzePassword = async () => {
                    try {
                        const response = await fetch('/analyze', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ password: password }),
                        });
                        
                        if (!response.ok) {
                            throw new Error('Erreur du serveur');
                        }
                        
                        const data = await response.json();
                        setAnalysis(data);
                        
                    } catch (error) {
                        console.error("Erreur lors de l'analyse:", error);
                        setAnalysis({ error: "Impossible de contacter le serveur d'analyse." });
                    } finally {
                        setIsLoading(false);
                    }
                };

                const handler = setTimeout(() => {
                    analyzePassword();
                }, 300);

                return () => {
                    clearTimeout(handler);
                };
            }, [password]); // Se déclenche à chaque changement de 'password'


            const CheckItem = ({ passed, label, critical }) => (
                <div className="flex items-center gap-2 text-sm">
                    {passed ? 
                        <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" /> : 
                        critical ?
                        <Skull className="w-4 h-4 text-red-500 flex-shrink-0" /> :
                        <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                    }
                    <span className={passed ? 'text-green-100' : critical ? 'text-red-300 font-semibold' : 'text-gray-400'}>
                        {label}
                    </span>
                </div>
            );

            return (
                <div className="min-h-screen bg-gradient-to-br from-black via-red-950 to-black p-6 text-gray-100">
                    <div className="max-w-2xl mx-auto">
                        <div className="text-center mb-8">
                            <div className="flex items-center justify-center mb-6">
                                <img 
                                    src="/static/logo.png"  /* MODIFIÉ: Utilise le chemin statique */
                                    alt="CSIUL Logo" 
                                    className="h-32 w-32 object-contain rounded-full border-4 border-red-700/50"
                                />
                            </div>
                            <h2 className="text-3xl font-bold text-red-500 mb-2">Teste ton mot de passe</h2>
                            <p className="text-gray-300">Club de Sécurité Informatique de l'Université Laval</p>
                        </div>
                        <div className="bg-black/50 backdrop-blur border-2 border-red-600/50 rounded-xl p-6 mb-6 shadow-lg shadow-red-900/20">
                            <label className="block text-white font-medium mb-3">
                                Entre ton mot de passe :
                            </label>
                            <div className="relative">
                                <input
                                    type={showPassword ? "text" : "password"}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="••••••••••••"
                                    className="w-full bg-black/70 border-2 border-gray-700 rounded-lg px-4 py-3 pr-12 text-white placeholder-gray-500 focus:outline-none focus:border-red-500 focus:ring-2 focus:ring-red-500/20 transition"
                                />
                                <button
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition p-1"
                                    type="button"
                                >
                                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                                </button>
                            </div>
                            <p className="text-xs text-gray-400 mt-2">
                                🔒 Sois sans crainte, rien n'est stocké ! L'analyse s'exécute sur un serveur sécurisé via l'API HIBP.
                            </p>
                        </div>
                        
                        {isLoading && (
                            <div className="flex justify-center items-center p-4 mb-6">
                                <div className="spinner"></div>
                            </div>
                        )}

                        {analysis && !isLoading && !analysis.error && (
                            <>
                                <div className="bg-black/50 backdrop-blur border-2 border-red-600/50 rounded-xl p-6 mb-6 shadow-lg shadow-red-900/20">
                                    <div className="flex items-center justify-between mb-3">
                                        <span className="text-white font-medium">Force du mot de passe :</span>
                                        <span className={`font-bold text-lg ${
                                            analysis.color === 'green' ? 'text-green-400' :
                                            analysis.color === 'blue' ? 'text-blue-400' :
                                            analysis.color === 'yellow' ? 'text-yellow-400' :
                                            analysis.color === 'orange' ? 'text-orange-400' :
                                            'text-red-500'
                                        }`}>
                                            {analysis.strength}
                                        </span>
                                    </div>
                                    <div className="w-full bg-gray-800 rounded-full h-4 overflow-hidden border border-gray-700">
                                        <div
                                            className={`h-full transition-all duration-500 ${
                                                analysis.color === 'green' ? 'bg-green-500' :
                                                analysis.color === 'blue' ? 'bg-blue-500' :
                                                analysis.color === 'yellow' ? 'bg-yellow-500' :
                                                analysis.color === 'orange' ? 'bg-orange-500' :
                                                'bg-red-600'
                                            }`}
                                            style={{ width: `${analysis.score}%` }}
                                        />
                                    </div>
                                </div>

                                <div className="bg-black/50 backdrop-blur border-2 border-red-600/50 rounded-xl p-6 mb-6 shadow-lg shadow-red-900/20">
                                    <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                                        <AlertTriangle className="w-5 h-5 text-red-500" />
                                        Critères de sécurité
                                    </h3>
                                    <div className="space-y-2">
                                        <CheckItem passed={analysis.checks.length} label="12 caractères minimum" />
                                        <CheckItem passed={analysis.checks.uppercase} label="Lettres majuscules (A-Z)" />
                                        <CheckItem passed={analysis.checks.lowercase} label="Lettres minuscules (a-z)" />
                                        <CheckItem passed={analysis.checks.numbers} label="Chiffres (0-9)" />
                                        <CheckItem passed={analysis.checks.special} label="Caractères spéciaux (!@#$%...)" />
                                        <CheckItem 
                                            passed={analysis.checks.notCommon}
                                            critical={!analysis.checks.notCommon}
                                            label={analysis.checks.notCommon ? 
                                                "Non trouvé (HIBP) ✓" : 
                                                "⚠️ TROUVÉ (HIBP) - Mot de passe COMPROMIS!"
                                            }
                                        />
                                    </div>
                                </div>

                                <div className={`backdrop-blur border-2 rounded-xl p-6 mb-6 shadow-lg ${
                                    analysis.secondsToCrack === 0 
                                        ? 'bg-red-950/70 border-red-500 shadow-red-900/50' 
                                        : analysis.secondsToCrack < 3600
                                        ? 'bg-orange-950/70 border-orange-500 shadow-orange-900/50'
                                        : 'bg-black/50 border-red-600/50 shadow-red-900/20'
                                }`}>
                                    <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
                                        <Clock className="w-5 h-5 text-red-500" />
                                        Temps estimé pour craquer ce mot de passe
                                    </h3>
                                    <div className={`rounded-lg p-4 ${
                                        analysis.secondsToCrack === 0 ? 'bg-red-900/50' : 
                                        analysis.secondsToCrack < 3600 ? 'bg-orange-900/50' :
                                        'bg-black/70'
                                    }`}>
                                        <div className="flex items-center gap-3">
                                            {analysis.secondsToCrack === 0 ? (
                                                <Skull className="w-8 h-8 text-red-500 flex-shrink-0" />
                                            ) : analysis.secondsToCrack < 3600 ? (
                                                <AlertTriangle className="w-8 h-8 text-orange-400 flex-shrink-0" />
                                            ) : (
                                                <Shield className="w-8 h-8 text-green-500 flex-shrink-0" />
                                            )}
                                            <div className="flex-1">
                                                <p className={`text-2xl font-bold ${
                                                    analysis.secondsToCrack === 0 ? 'text-red-400' : 
                                                    analysis.secondsToCrack < 3600 ? 'text-orange-300' :
                                                    'text-white'
                                                }`}>
                                                    {formatTime(analysis.secondsToCrack)}
                                                </p>
                                                <p className="text-sm text-gray-400 mt-1">
                                                    {analysis.secondsToCrack === 0 
                                                        ? 'Le mot de passe est dans une base de données publique!'
                                                        : `Méthode : ${analysis.crackMethod}`
                                                    }
                                                </p>
                                                {analysis.hashType && analysis.secondsToCrack > 0 && (
                                                    <p className="text-xs text-gray-500 mt-1">
                                                        Hash : {analysis.hashType} • Matériel : 8x RTX 4090
                                                        {analysis.entropy && ` • Entropie : ${analysis.entropy} bits`}
                                                    </p>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {analysis.suggestions.length > 0 && (
                                    <div className={`backdrop-blur border-2 rounded-xl p-6 shadow-lg ${
                                        analysis.checks.notCommon === false
                                            ? 'bg-red-950/70 border-red-500 shadow-red-900/50'
                                            : 'bg-gradient-to-r from-orange-950/30 to-red-950/30 border-red-600/30 shadow-red-900/20'
                                    }`}>
                                        <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
                                            💡 Conseils d'amélioration
                                        </h3>
                                        <ul className="space-y-2">
                                            {analysis.suggestions.map((suggestion, idx) => (
                                                <li key={idx} className="text-gray-200 text-sm flex items-start gap-2">
                                                    <span className="text-red-500 flex-shrink-0">→</span>
                                                    <span>{suggestion}</span>
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                )}
                            </>
                        )}

                        <div className="text-center mt-8 text-gray-400 text-sm space-y-2">
                            <p className="text-xs text-gray-500 mt-4">
                                Calculs basés sur les vitesses réelles de Hashcat (8x RTX 4090)<br/>
                                Algorithme : Détection de patterns + Force brute + Entropie
                            </p>
                        </div>
                    </div>
                </div>
            );
        }

        const root = ReactDOM.createRoot(document.getElementById('root'));
        root.render(<PasswordTester />);

    </script>
    {% endraw %}
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

if __name__ == '__main__':
    app.run(debug=True, port=5000)