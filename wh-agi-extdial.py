#!/opt/agi-venv/bin/python3
import sys, os, json, re
from difflib import SequenceMatcher
from openai import OpenAI

os.environ["OPENAI_API_KEY"] = "sk-proj--eyvtwc3G7jntYA"

EXT_MAP = [
    {"text": "קביעת תור מחדש",   "number": "1000"},  # reschedule (alt)
    {"text": "מכירות",           "number": "1001"},  # sales
    {"text": "תמיכה",            "number": "1002"},  # support
    {"text": "חשבונאות",         "number": "1003"},  # accounting
    {"text": "חשבונות",          "number": "1004"},  # alt for accounting (accounts)
    {"text": "קבלה",             "number": "1005"},  # reception
    {"text": "מזכירות",          "number": "1006"},  # reception/secretariat
    {"text": "משרד הרופא",       "number": "1007"},  # doctor's office
    {"text": "רופא",             "number": "1008"},  # doctor (short)
    {"text": "ביטול",            "number": "1009"},  # cancel
    {"text": "תזמון מחדש",       "number": "1010"},  # reschedule
]

MAX_CHARS = 2000
DEFAULT_MODEL = "gpt-4o-mini-transcribe"

def agi_read_env():
    env = {}
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            break
        if ":" in line:
            k, v = line.split(":", 1)
            env[k.strip()] = v.strip()
    return env

def agi_set_var(name, value):
    if value is None:
        value = ""
    safe = str(value).replace("\n", " ").replace("\r", " ")
    print(f'SET VARIABLE {name} "{safe}"')
    sys.stdout.flush()

_HEBREW_DIACRITICS = re.compile(r"[\u0591-\u05C7]")

def normalize(s: str):
    s = _HEBREW_DIACRITICS.sub("", s or "")
    s = s.lower().strip()
    s = re.sub(r"[\t\n\r]+", " ", s)
    s = re.sub(r"[^\w\u0590-\u05FF\u0980-\u09FF\s-]+", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()

def best_match(transcript: str, ext_map, fuzzy_threshold=0.80):
    tnorm = normalize(transcript)

    for item in ext_map:
        key = normalize(item["text"])
        if key and key in tnorm:
            return item["text"], item["number"]

    best = ("", "", 0.0)
    for item in ext_map:
        key = normalize(item["text"])
        if not key:
            continue
        ratio = SequenceMatcher(None, key, tnorm).ratio()
        if ratio > best[2]:
            best = (item["text"], item["number"], ratio)

    if best[2] >= fuzzy_threshold:
        return best[0], best[1]
    return "", ""

def transcribe(path: str, model=DEFAULT_MODEL):
    client = OpenAI()
    lang_hint = os.environ.get("ASR_LANG_HINT", "he").strip() or None
    with open(path, "rb") as f:
        kwargs = dict(model=model, file=f, response_format="text")
        if lang_hint:
            kwargs["language"] = lang_hint
        txt = client.audio.transcriptions.create(**kwargs)
    return (txt or "").strip()[:MAX_CHARS]

def main():
    agi_read_env()
    if len(sys.argv) < 2:
        agi_set_var("ASR", "ERROR: Missing audio argument")
        agi_set_var("ASR_TEXT", "")
        agi_set_var("ASR_NUMBER", "")
        return

    audio_path = sys.argv[1]
    if not os.path.exists(audio_path):
        agi_set_var("ASR", f"ERROR: File not found {audio_path}")
        agi_set_var("ASR_TEXT", "")
        agi_set_var("ASR_NUMBER", "")
        return

    model = os.environ.get("ASR_MODEL", DEFAULT_MODEL)

    try:
        text = transcribe(audio_path, model=model)
        #asr_text, asr_num = best_match(text, EXT_MAP)
        agi_set_var("ASR", text)
        #agi_set_var("ASR_TEXT", asr_text)
        #agi_set_var("ASR_NUMBER", asr_num)
    except Exception as e:
        agi_set_var("ASR", f"ERROR: {e}")
        #agi_set_var("ASR_TEXT", "")
        #agi_set_var("ASR_NUMBER", "")

if __name__ == "__main__":
    main()
