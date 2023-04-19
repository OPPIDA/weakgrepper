from enum import Enum

# Print the result in color depending on the severity.
# INFO: green
# WARNING : yellow
# CRITIC : red
severity = Enum("severity", "INFO WARNING CRITIC")

# Feel free to add new constants has you want.
# Regex are case insensive by default to force a pattern case sensitive, use a byte string (custom method of distinguishing).
PATTERNS = {
    "MD2": [
        # Sbox
        (severity.CRITIC, ["41[ \n]?,[ \n]?46[ \n]?,[ \n]?67[ \n]?,[ \n]?201[ \n]?,[ \n]?162[ \n]?,[ \n]?216",
                           "0x29[ \n]?,[ \n]?0x2E[ \n]?,[ \n]?0x43[ \n]?,[ \n]?0xC9[ \n]?,[ \n]?0xA2[ \n]?,[ \n]?0xD8"]),
        (severity.WARNING, ["MD2"])
    ],
    "MD4": [
        # same constants as SHA-1 but MD4 is much rarer, don't search for constants to remove false positives
        (severity.WARNING, ["MD4"])
    ],
    "MD5": [
        # The array order is the priority, if one of the regex matches, the search stops for this file.
        # Constants
        (severity.CRITIC, ["0xD76AA478", "0xF61E2562", "3614090360", "4129170786"]),
        # Generic name
        (severity.WARNING, ["MD5"])
    ],
    "RIPEMD-128/256": [
        (severity.WARNING, ["RIPEMD[-]?128", "RIPEMD[-]?256"])
    ],
    "SHA-1": [
        (severity.CRITIC, ["0x5A827999", "0x6ED9EBA1", "1518500249", "1859775393"]),
        (severity.WARNING, ["SHA[-_]?1"])
    ],
    "Blowfish": [
        (severity.CRITIC, ["0x243F6A88", "0x85A308D3", "608135816", "2242054355"]),
        (severity.WARNING, ["Blowfish"])
    ],
    "CAST": [
        # case sensitive to reduce false positives on the word "cast" (convert)
        (severity.WARNING, [b"CAST"])
    ],
    "CRC32": [
        (severity.CRITIC, ["0x04c11db7", "0x09823b6e", "79764919", "159529838"]),
        (severity.WARNING, ["CRC[-_]32"])
    ],
    "CRC64": [
        (severity.CRITIC, ["0x42F0E1EBA9EA3693", "4823603603198064275"]),
        (severity.WARNING, ["CRC[-_]64"])
    ],
    "RC2": [
        (severity.CRITIC, ["217[ \n]?,[ \n]?120[ \n]?,[ \n]?249[ \n]?,[ \n]?196[ \n]?,[ \n]?25[ \n]?,[ \n]?221",
                           "0xd9[ \n]?,[ \n]?0x78[ \n]?,[ \n]?0xf9[ \n]?,[ \n]?0xc4[ \n]?,[ \n]?0x19[ \n]?,[ \n]?0xdd"]),
        (severity.WARNING, ["RC2"])
    ],
    "RC4": [
        (severity.WARNING, ["RC4", "KSA", "PRGA"])
    ],
    "DES": [
        (severity.CRITIC,
         ["57[ \n]?,[ \n]?49[ \n]?,[ \n]?41[ \n]?,[ \n]?33[ \n]?,[ \n]?25[ \n]?,[ \n]?17[ \n]?,[ \n]?9",
          "0x39[ \n]?,[ \n]?0x31[ \n]?,[ \n]?0x29[ \n]?,[ \n]?0x21[ \n]?,[ \n]?0x19[ \n]?,[ \n]?0x11[ \n]?,[ \n]?0x9"]),
        (severity.WARNING, ["Triple DES", b"[3T]?DES"])
    ],
    "ECB (mode of operation)": [
        # Generic ECB mode detection
        (severity.WARNING, ["ECB"])
    ],
    "CFB (mode of operation)": [
        # Generic truncated CFB mode detection
        (severity.WARNING, ["CFB1", "CFB8"])
    ],
    "CBC-MAC": [
        (severity.WARNING, ["CBC-MAC"])
    ],
    "AES T-BOX(vulnerable cache-timing attack)": [
        # Big endian and small endian constants
        (severity.CRITIC,
         ["0xc66363a5", "0x51f4a750", "3328402341", "1374988112", "0xa56363c6", "1353184337", "2774754246"]),
    ],
    "Mersenne twister": [
        (severity.CRITIC, ["0x9d2c5680", "0xefc60000", "2636928640", "4022730752"]),
        (severity.WARNING, ["MT19937", "mersenne twister", "mersenne"]),
        # C random
        (severity.WARNING, [b"srand\(", b"rand\("]),
        # PHP random
        (severity.WARNING, [b"mt_rand\(", b"mt_randmax\(", b"mt_srand\("])
    ],
    "Dual EC DRBG": [
        (severity.CRITIC, [
            "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
            "1b9fa3e518d683c6b65763694ac8efbaec6fab44f2276171a42726507dd08add4c3b3f4c1ebc5b1222ddba077f722943b24c3edfa0f85fe24d0c8c01591f0be6f63",
            "9585320EEAF81044F20D55030A035B11BECE81C785E6C933E4A8A131F65781",
            "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
            "1f3bdba585295d9a1110d1df1f9430ef8442c5018976ff3437ef91b81dc0b8132c8d5c39c32d0e004a3092b7d327c0e7a4d26d2c7b69b58f9066652911e457779de",
        ]),
    ],
    "DH groups": [
        (severity.WARNING, [b"DH[0-9]+"])
    ],
    "PKCS#1 v1_5": [
        (severity.WARNING, ["PKCS#?1[-_ ]v1.5", "PKCS#?1.5", "PKCS#?1 version 1.5"])
    ],
    "Official References": [
        (severity.INFO, ["RFC [0-9]{4}", "SP[0-9]{3}[-_ ][0-9]+[A-Z]?"])
    ],
    "Suspicious comments": [
        (severity.INFO,
         ["TO[ ]?DO", "fix[ ]?me", "hard[ ]?coded", "danger", "CVE", "bug", "shit", "fuck", "merde", "a corriger",
          "a faire", "en dur"])
    ],
    "Private Keys": [
        (severity.CRITIC, [b"BEGIN PRIVATE KEY", b"BEGIN RSA PRIVATE KEY"])
    ]
}
