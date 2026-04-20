"""
Password Strength Analyzer
أداة لتحليل قوة كلمات السر وتقييم أمانها
"""

import re
import hashlib
import math
import requests
from typing import Dict, List, Tuple


class PasswordAnalyzer:
    """محلل قوة كلمة السر"""

    # قائمة كلمات السر الأكثر شيوعاً (أمثلة)
    COMMON_PASSWORDS = {
        "123456", "password", "123456789", "12345678", "12345",
        "qwerty", "abc123", "111111", "123123", "admin",
        "letmein", "welcome", "monkey", "1234567890", "password1",
        "iloveyou", "sunshine", "princess", "dragon", "passw0rd"
    }

    def __init__(self, password: str):
        self.password = password
        self.length = len(password)

    def check_length(self) -> Tuple[int, str]:
        """فحص طول كلمة السر"""
        if self.length < 8:
            return 0, "قصيرة جداً (أقل من 8 أحرف)"
        elif self.length < 12:
            return 1, "مقبولة (8-11 حرف)"
        elif self.length < 16:
            return 2, "جيدة (12-15 حرف)"
        else:
            return 3, "ممتازة (16+ حرف)"

    def check_character_variety(self) -> Dict[str, bool]:
        """فحص تنوع الأحرف"""
        return {
            "lowercase": bool(re.search(r'[a-z]', self.password)),
            "uppercase": bool(re.search(r'[A-Z]', self.password)),
            "digits": bool(re.search(r'\d', self.password)),
            "special": bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', self.password)),
        }

    def calculate_entropy(self) -> float:
        """حساب الإنتروبي (مقياس العشوائية)"""
        charset_size = 0
        variety = self.check_character_variety()

        if variety["lowercase"]:
            charset_size += 26
        if variety["uppercase"]:
            charset_size += 26
        if variety["digits"]:
            charset_size += 10
        if variety["special"]:
            charset_size += 32

        if charset_size == 0:
            return 0.0

        entropy = self.length * math.log2(charset_size)
        return round(entropy, 2)

    def estimate_crack_time(self) -> str:
        """تقدير الوقت اللازم لكسر كلمة السر"""
        entropy = self.calculate_entropy()
        # افتراض: 10 مليار محاولة في الثانية (هجوم قوي)
        guesses_per_second = 10_000_000_000
        total_combinations = 2 ** entropy
        seconds = total_combinations / (2 * guesses_per_second)

        if seconds < 1:
            return "أقل من ثانية ⚠️"
        elif seconds < 60:
            return f"{seconds:.1f} ثانية ⚠️"
        elif seconds < 3600:
            return f"{seconds/60:.1f} دقيقة ⚠️"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} ساعة"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} يوم"
        elif seconds < 31536000 * 100:
            return f"{seconds/31536000:.1f} سنة ✓"
        elif seconds < 31536000 * 1_000_000:
            return f"{seconds/31536000:,.0f} سنة ✓"
        else:
            return "ملايين السنين ✓✓"

    def is_common(self) -> bool:
        """فحص إذا كانت كلمة السر من الشائعة"""
        return self.password.lower() in self.COMMON_PASSWORDS

    def check_pwned(self) -> Tuple[bool, int]:
        """
        فحص كلمة السر عبر HaveIBeenPwned API
        باستخدام k-Anonymity - يرسل فقط أول 5 أحرف من الهاش
        """
        try:
            sha1 = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            url = f"https://api.pwnedpasswords.com/range/{prefix}"

            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                return False, 0

            for line in response.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    return True, int(count)

            return False, 0
        except Exception:
            return False, -1  # خطأ بالاتصال

    def get_score(self) -> int:
        """حساب النتيجة الإجمالية من 100"""
        score = 0

        # الطول (30 نقطة)
        length_score, _ = self.check_length()
        score += length_score * 10

        # التنوع (40 نقطة)
        variety = self.check_character_variety()
        score += sum(variety.values()) * 10

        # الإنتروبي (30 نقطة)
        entropy = self.calculate_entropy()
        if entropy >= 80:
            score += 30
        elif entropy >= 60:
            score += 20
        elif entropy >= 40:
            score += 10

        # خصم إذا كانت شائعة
        if self.is_common():
            score = max(0, score - 50)

        return min(100, score)

    def get_strength_label(self) -> str:
        """تصنيف قوة كلمة السر"""
        score = self.get_score()
        if score < 30:
            return "ضعيفة جداً 🔴"
        elif score < 50:
            return "ضعيفة 🟠"
        elif score < 70:
            return "متوسطة 🟡"
        elif score < 90:
            return "قوية 🟢"
        else:
            return "قوية جداً ✅"

    def get_recommendations(self) -> List[str]:
        """اقتراحات لتحسين كلمة السر"""
        recommendations = []
        variety = self.check_character_variety()

        if self.length < 12:
            recommendations.append("زيدي الطول إلى 12 حرف على الأقل")
        if not variety["lowercase"]:
            recommendations.append("أضيفي أحرف صغيرة (a-z)")
        if not variety["uppercase"]:
            recommendations.append("أضيفي أحرف كبيرة (A-Z)")
        if not variety["digits"]:
            recommendations.append("أضيفي أرقام (0-9)")
        if not variety["special"]:
            recommendations.append("أضيفي رموز خاصة (!@#$...)")
        if self.is_common():
            recommendations.append("⚠️ تجنّبي كلمات السر الشائعة")

        return recommendations

    def analyze(self) -> Dict:
        """تحليل شامل لكلمة السر"""
        _, length_desc = self.check_length()
        variety = self.check_character_variety()
        pwned, pwned_count = self.check_pwned()

        return {
            "password_length": self.length,
            "length_description": length_desc,
            "character_variety": variety,
            "entropy_bits": self.calculate_entropy(),
            "estimated_crack_time": self.estimate_crack_time(),
            "is_common_password": self.is_common(),
            "found_in_breaches": pwned,
            "breach_count": pwned_count,
            "score": self.get_score(),
            "strength": self.get_strength_label(),
            "recommendations": self.get_recommendations(),
        }


def print_report(analyzer: PasswordAnalyzer):
    """طباعة تقرير منسق"""
    result = analyzer.analyze()

    print("\n" + "="*60)
    print("          تقرير تحليل كلمة السر")
    print("="*60)
    print(f"\n📏 الطول: {result['password_length']} حرف - {result['length_description']}")

    print(f"\n🔤 تنوع الأحرف:")
    variety = result['character_variety']
    print(f"   • أحرف صغيرة (a-z): {'✓' if variety['lowercase'] else '✗'}")
    print(f"   • أحرف كبيرة (A-Z): {'✓' if variety['uppercase'] else '✗'}")
    print(f"   • أرقام (0-9):      {'✓' if variety['digits'] else '✗'}")
    print(f"   • رموز خاصة:        {'✓' if variety['special'] else '✗'}")

    print(f"\n🧮 الإنتروبي: {result['entropy_bits']} بت")
    print(f"⏱️  الوقت المتوقع لكسرها: {result['estimated_crack_time']}")

    if result['is_common_password']:
        print(f"\n⚠️  تحذير: هذه من كلمات السر الأكثر شيوعاً!")

    if result['found_in_breaches']:
        print(f"\n🚨 تحذير شديد: وُجدت في {result['breach_count']:,} تسريب!")
    elif result['breach_count'] == -1:
        print(f"\n⚠️  تعذّر الاتصال بقاعدة بيانات التسريبات")
    else:
        print(f"\n✅ لم تُعثر عليها في قواعد بيانات التسريبات المعروفة")

    print(f"\n📊 النتيجة: {result['score']}/100")
    print(f"💪 قوة كلمة السر: {result['strength']}")

    if result['recommendations']:
        print(f"\n💡 توصيات للتحسين:")
        for rec in result['recommendations']:
            print(f"   • {rec}")

    print("\n" + "="*60 + "\n")


def main():
    print("\n🔐 محلل قوة كلمات السر")
    print("-" * 40)

    try:
        password = input("أدخلي كلمة السر للتحليل: ")
        if not password:
            print("❌ لم تُدخلي كلمة سر!")
            return

        analyzer = PasswordAnalyzer(password)
        print_report(analyzer)
    except KeyboardInterrupt:
        print("\n\nتم الإلغاء.")


if __name__ == "__main__":
    main()
