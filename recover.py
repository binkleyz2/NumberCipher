#!/usr/bin/env python3
"""Independent decoder/encoder for Cipherwords codes.

Lets you recover your text on any computer even without the apps.
Requires:  pip3 install cryptography

  python3 recover.py decrypt "ACOUSTIC PILOT WAGON ..."     (old letter codes "ABCDE FGHJK ..." work too)
  python3 recover.py encrypt "any text you like"
  python3 recover.py decrypt -                            (read the code or text from standard input)

Binary format v2: version(1)=2 | rounds(4, big-endian) | salt(16) | nonce(12) | ciphertext | tag(16)
Binary format v1: version(1)=1 | salt(16) | nonce(12) | ciphertext | tag(16), fixed 2,000,000 rounds
Key = PBKDF2-HMAC-SHA256(NFC(passphrase), salt, rounds); cipher = AES-256-GCM with the header as AAD.
Plaintext = UTF-8 text padded with 0x00 to the next multiple of 16 bytes (always at least one 0x00).

Written as words (since 1.5): the bytes are read as a bit string, most significant bit first,
split into 11-bit numbers (the last one padded with 0 bits), and each number picks a word from
the BIP39 English list below (2,048 words; the first 4 letters of each word are unique). Since
every v2 code is 49 + 16k bytes long, the byte count is the largest n <= 11*words/8 with
n % 16 == 1, and ceil(8n/11) must equal the word count.
Written as letters (1.0-1.4, still read): each byte -> two letters from "ABCDEFGHJKLMNPQR".
A code containing any letter outside that set is read as words.
"""
import getpass, hashlib, os, re, struct, sys, time, unicodedata
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

V1_ROUNDS, SALT, PAD = 2_000_000, 16, 16
MIN_ROUNDS, MAX_ROUNDS, TARGET_SECONDS = 2_000_000, 1_000_000_000, 10
MAX_TEXT_BYTES = 20_000
ALPHA = "ABCDEFGHJKLMNPQR"
WORDS_PER_LINE = 6

MSG_MALFORMED = "That doesn't look like a Cipherwords code (check for typos or missing letters)."
MSG_WORD_COUNT = "A word seems to be missing or extra. Check the code against the original."


def key(pw: str, salt: bytes, rounds: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", unicodedata.normalize("NFC", pw).encode(), salt, rounds, 32)


def calibrate() -> int:
    probe = 1_000_000
    t = time.perf_counter()
    key("calibration-passphrase", bytes([7]) * SALT, probe)
    est = probe / (time.perf_counter() - t) * TARGET_SECONDS
    return int(min(max(round(est / 100_000) * 100_000, MIN_ROUNDS), MAX_ROUNDS // 2))


# ---- Letters (codes made by versions 1.0-1.4) ------------------------------------------------

def to_letters(b: bytes) -> str:
    s = "".join(ALPHA[x >> 4] + ALPHA[x & 15] for x in b)
    return " ".join(s[i:i + 5] for i in range(0, len(s), 5))


def from_letters(code: str) -> bytes:
    s = "".join(c for c in code.upper() if not c.isspace() and c != "-")
    if not s or len(s) % 2 or any(c not in ALPHA for c in s):
        raise ValueError(MSG_MALFORMED)
    return bytes(ALPHA.index(s[i]) << 4 | ALPHA.index(s[i + 1]) for i in range(0, len(s), 2))


# ---- Words ------------------------------------------------------------------------------------

def to_words(b: bytes) -> str:
    bits = int.from_bytes(b, "big")
    count = (len(b) * 8 + 10) // 11
    bits <<= count * 11 - len(b) * 8
    idx = [(bits >> (11 * (count - 1 - i))) & 0x7FF for i in range(count)]
    w = [WORDS[i].upper() for i in idx]
    return "\n".join(" ".join(w[i:i + WORDS_PER_LINE]) for i in range(0, len(w), WORDS_PER_LINE))


def word_index(token: str, position: int) -> int:
    t = token.lower()
    if t in WORD_INDEX:
        return WORD_INDEX[t]
    if len(t) >= 4 and t[:4] in PREFIX_INDEX:
        return PREFIX_INDEX[t[:4]]
    raise ValueError(f"“{token.upper()}” (word {position}) isn't one of the code words. Check its spelling.")


def from_words(code: str) -> bytes:
    tokens = re.findall(r"[A-Za-z]+", code)
    count = len(tokens)
    idx = [word_index(t, i + 1) for i, t in enumerate(tokens)]
    n = count * 11 // 8
    n -= (n - 1) % 16
    if n < 49 + PAD or (n * 8 + 10) // 11 != count:
        raise ValueError(MSG_WORD_COUNT)
    bits = 0
    for i in idx:
        bits = bits << 11 | i
    spare = count * 11 - n * 8
    if bits & ((1 << spare) - 1):
        raise ValueError("The last word of the code looks wrong. Check it for a typo.")
    return (bits >> spare).to_bytes(n, "big")


def is_word_code(code: str) -> bool:
    return any(c.isascii() and c.isalpha() and c.upper() not in ALPHA for c in code)


def decode(code: str) -> bytes:
    return from_words(code) if is_word_code(code) else from_letters(code)


# ---- Encrypt / decrypt ------------------------------------------------------------------------

def clean_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        raise ValueError("Enter some text to encrypt.")
    if "\0" in text:
        raise ValueError("The text contains a null character, which can't be encrypted.")
    if len(text.encode()) > MAX_TEXT_BYTES:
        raise ValueError("That's too much text (the limit is 20,000 bytes, about 20,000 English characters).")
    return text


def encrypt(text: str, pw: str, rounds: int | None = None) -> str:
    text = clean_text(text)
    if not pw:
        raise ValueError("Enter a passphrase.")
    rounds = rounds or calibrate()
    plain = text.encode()
    plain += b"\0" * ((len(plain) // PAD + 1) * PAD - len(plain))
    salt = os.urandom(SALT)
    header = bytes([2]) + struct.pack(">I", rounds) + salt
    nonce = os.urandom(12)
    return to_words(header + nonce + AESGCM(key(pw, salt, rounds)).encrypt(nonce, plain, header))


def read_header(b: bytes, words: bool) -> tuple[int, int]:
    if b[0] == 1:
        return 1 + SALT, V1_ROUNDS
    if b[0] == 2:
        if len(b) < 5 + SALT:
            raise ValueError(MSG_MALFORMED)
        rounds = struct.unpack(">I", b[1:5])[0]
        if not 100_000 <= rounds <= MAX_ROUNDS:
            raise ValueError(MSG_MALFORMED)
        return 5 + SALT, rounds
    if b[0] == 0:
        raise ValueError(MSG_MALFORMED)
    if b[0] < 16:  # future versions all start with "A" (letters) / ACOUSTIC.. range (words)
        raise ValueError("This code was made by a newer version of Cipherwords. Update this app to decrypt it.")
    if words:
        raise ValueError("The first word of the code looks wrong. Check it for a typo.")
    raise ValueError("The first letter of a code is always A. Check the start of the code for a typo.")


def decrypt(code: str, pw: str) -> str:
    words = is_word_code(code)
    b = from_words(code) if words else from_letters(code)
    hlen, rounds = read_header(b, words)
    if len(b) < hlen + 12 + 16:
        raise ValueError(MSG_MALFORMED)
    header, salt = b[:hlen], b[hlen - SALT:hlen]
    nonce, ct = b[hlen:hlen + 12], b[hlen + 12:]
    return AESGCM(key(pw, salt, rounds)).decrypt(nonce, ct, header).rstrip(b"\0").decode()


WORDS = """
abandon ability able about above absent absorb abstract absurd abuse access accident account accuse
achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust
admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport
aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always
amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce
annual another answer antenna antique anxiety any apart apology appear apple approve april arch
arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist
artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract
auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful
awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely
bargain barrel base basic basket battle beach bean beauty because become beef before begin behave
behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind
biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse
blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom
bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk
broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet
bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus
cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital
captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch
category cattle caught cause caution cave ceiling celery cement census century cereal certain chair
chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken
chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city
civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock
clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin
collect color column combine come comfort comic common company concert conduct confirm congress
connect consider control convince cook cool copper copy coral core corn correct cost cotton couch
country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy
cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise
crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion
custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris
decade december decide decline decorate decrease deer defense define defy degree delay deliver
demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design
desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet
differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss
disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate
donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink
drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn
earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder
electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ
empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy
enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode
erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact
example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit
exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade
faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue
fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber
fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit
fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly
foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil
foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel
fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic
garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift
giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow
glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape
grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar
gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard
head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire
history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host
hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid
ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate indoor industry infant inflict inform
inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside
inspire install intact interest into invest invite involve iron island isolate issue item ivory
jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle
junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite
kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later
latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal
legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life
lift light like limb limit link lion liquid list little live lizard load loan lobster local lock
logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics
machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual
maple marble march margin marine market marriage mask mass master match material math matrix matter
maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu
mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum
minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment
monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse
move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth
naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve
nest net network neutral never news next nice night noble noise nominee noodle normal north nose
notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure
observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic
omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary
organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner
oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent
park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear
peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase
physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place
planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond
pony pool popular portion position possible post potato pottery poverty powder power practice praise
predict prefer prepare present pretty prevent price pride primary print priority prison private
prize problem process produce profit program project promote proof property prosper protect proud
provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push
put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack
radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor
ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse
region regret regular reject relax release relief rely remain remember remind remove render renew
rent reopen repair repeat replace report require rescue resemble resist resource response result
retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle
right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof
rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle
sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save
say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script
scrub sea search season seat second secret section security seed seek segment select sell seminar
senior sense sentence series service session settle setup seven shadow shaft shallow share shed
shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug
shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing
siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice
slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow
soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort
soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice
spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze
squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo
stick still sting stock stomach stone stool story stove strategy street strike strong struggle
student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit
summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect
sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup
system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten
tenant tennis tent term test text thank that theme then theory there they thing this thought three
thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast
tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top
topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic
tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip
trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn
turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover
under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil
update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant
vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture
venue verb verify version very vessel veteran viable vibrant vicious victory video view village
vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote
voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way
wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel
when where whip whisper wide width wife wild will win window wine wing wink winner winter wire
wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle
wrist write wrong yard year yellow you young youth zebra zero zone zoo
""".split()
WORD_INDEX = {w: i for i, w in enumerate(WORDS)}
PREFIX_INDEX = {w[:4]: i for i, w in enumerate(WORDS)}
assert len(WORDS) == 2048 and len(PREFIX_INDEX) == 2048
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"  # official BIP39 english.txt
assert hashlib.sha256(("\n".join(WORDS) + "\n").encode()).hexdigest() == WORDLIST_SHA256


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("encrypt", "decrypt"):
        sys.exit(__doc__)
    arg = sys.stdin.read() if sys.argv[2] == "-" else sys.argv[2]
    pw = getpass.getpass("Passphrase: ")
    if sys.argv[1] == "encrypt" and getpass.getpass("Passphrase again: ") != pw:
        sys.exit("The passphrases don't match.")
    print("Working (about 10 seconds)…", file=sys.stderr)
    try:
        print((encrypt if sys.argv[1] == "encrypt" else decrypt)(arg, pw))
    except InvalidTag:
        sys.exit("Wrong passphrase, or the code was altered.")
    except ValueError as e:
        sys.exit(str(e))
