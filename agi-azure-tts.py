#!/opt/agi-venv/bin/python3
# -*- coding: utf-8 -*-
import os, sys, html, tempfile
import requests

REGION     = os.environ.get("AZURE_REGION", "westeurope")
ENDPOINT   = os.environ.get("AZURE_TTS_ENDPOINT", "https://westeurope.tts.speech.microsoft.com/cognitiveservices/v1")

KEY1 = os.environ.get("AZURE_TTS_KEY1", "")
KEY2 = os.environ.get("AZURE_TTS_KEY2", "")

OUTPUT_FORMAT = "riff-8khz-16bit-mono-pcm"
DEFAULT_LANG  = "en-US"
DEFAULT_VOICE = "en-US-AriaNeural"

TIMEOUT = 15  # seconds

def agi_read_env():
    env = {}
    while True:
        line = sys.stdin.readline()
        if not line: break
        line = line.strip()
        if not line: break
        if ":" in line:
            k, v = line.split(":", 1)
            env[k.strip()] = v.strip()
    return env

def agi_set_var(name, value):
    if value is None: value = ""
    safe = str(value).replace("\n", " ").replace("\r", " ")
    sys.stdout.write(f'SET VARIABLE {name} "{safe}"\n')
    sys.stdout.flush()

def build_ssml(text, lang, voice):
    escaped = html.escape(text, quote=False)
    return f"""<speak version="1.0" xml:lang="{lang}">
  <voice name="{voice}">{escaped}</voice>
</speak>"""

def synthesize(ssml, key):
    headers = {
        "Ocp-Apim-Subscription-Key": key,
        "Content-Type": "application/ssml+xml",
        "X-Microsoft-OutputFormat": OUTPUT_FORMAT,
        "User-Agent": "asterisk-agi-azure-tts/1.0",
    }
    resp = requests.post(ENDPOINT, data=ssml.encode("utf-8"), headers=headers, timeout=TIMEOUT)
    return resp

def write_file(bytes_data, out_path=None):
    if out_path:
        target = out_path
        base = os.path.dirname(target)
        if base and not os.path.isdir(base):
            os.makedirs(base, exist_ok=True)
    else:
        fd, target = tempfile.mkstemp(prefix="tts-", suffix=".wav", dir="/dev/shm")
        os.close(fd)
    with open(target, "wb") as f:
        f.write(bytes_data)
    return os.path.abspath(target)

def main():
    agi_read_env()  # consume AGI channel env

    text  = sys.argv[1] if len(sys.argv) > 1 else ""
    outfp = sys.argv[2] if len(sys.argv) > 2 else ""
    lang  = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_LANG
    voice = sys.argv[4] if len(sys.argv) > 4 else DEFAULT_VOICE

    if not text.strip():
        agi_set_var("TTS_STATUS", "ERROR")
        agi_set_var("TTS_FILE", "")
        agi_set_var("TTS_ERROR", "No text provided")
        return

    ssml = build_ssml(text.strip(), lang.strip(), voice.strip())

    try:
        for key in (KEY1, KEY2):
            if not key:  # skip empty
                continue
            r = synthesize(ssml, key)
            if r.status_code == 200 and r.content:
                out_file = write_file(r.content, outfp or None)
                agi_set_var("TTS_STATUS", "OK")
                agi_set_var("TTS_FILE", out_file)
                agi_set_var("TTS_ERROR", "")
                return
            if r.status_code in (401, 403):
                continue
            err = f"HTTP {r.status_code} {r.text[:120]}"
            agi_set_var("TTS_STATUS", "ERROR")
            agi_set_var("TTS_FILE", "")
            agi_set_var("TTS_ERROR", err)
            return

        agi_set_var("TTS_STATUS", "ERROR")
        agi_set_var("TTS_FILE", "")
        agi_set_var("TTS_ERROR", "Authorization failed with provided keys")
        return

    except Exception as e:
        agi_set_var("TTS_STATUS", "ERROR")
        agi_set_var("TTS_FILE", "")
        agi_set_var("TTS_ERROR", str(e))
        return

if __name__ == "__main__":
    main()
